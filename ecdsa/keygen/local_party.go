// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/golang/protobuf/proto"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		temp localTempData
		data LocalPartySaveData

		// outbound messaging
		out chan<- tss.Message
		end chan<- LocalPartySaveData
	}

	localMessageStore struct {
		kgRound1Messages,
		kgRound2Message1s,
		kgRound2Message2s,
		kgRound3Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after keygen)
		ui            *big.Int // used for tests
		KGCs          []cmt.HashCommitment
		vs            vss.Vs
		shares        vss.Shares
		deCommitPolyG cmt.HashDeCommitment
	}

	LocalPreParams struct {
		PaillierSK        *paillier.PrivateKey // ski
		NTildei, H1i, H2i *big.Int             // n-tilde, h1, h2
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalPreParams
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// n-tilde, h1, h2 for range proofs
		NTildej, H1j, H2j []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj       []*crypto.ECPoint     // Xj
		PaillierPKs []*paillier.PublicKey // pkj

		// used for test assertions (may be discarded)
		ECDSAPub *crypto.ECPoint // y
	}
)

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil && preParams.NTildei != nil && preParams.H1i != nil && preParams.H2i != nil
}

// Exported, used in `tss` client
func NewLocalParty(
	params *tss.Parameters,
	out chan<- tss.Message,
	end chan<- LocalPartySaveData,
	optionalPreParams ...LocalPreParams,
) tss.Party {
	partyCount := params.PartyCount()
	data := LocalPartySaveData{}
	// when `optionalPreParams` is provided we'll use the pre-computed primes instead of generating them from scratch
	if 0 < len(optionalPreParams) {
		if 1 < len(optionalPreParams) {
			panic(errors.New("keygen.NewLocalParty expected 0 or 1 item in `optionalPreParams`"))
		}
		if !optionalPreParams[0].Validate() {
			panic(errors.New("keygen.NewLocalParty: `optionalPreParams` failed to validate"))
		}
		data.LocalPreParams = optionalPreParams[0]
	}
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.kgRound1Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound2Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.kgRound3Messages = make([]tss.ParsedMessage, partyCount)
	// temp data init
	p.temp.KGCs = make([]cmt.HashCommitment, partyCount)
	// save data init
	p.data.BigXj = make([]*crypto.ECPoint, partyCount)
	p.data.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	p.data.NTildej = make([]*big.Int, partyCount)
	p.data.H1j, p.data.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, "keygen")
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, "keygen")
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {

	case *KGRound1Message:
		p.temp.kgRound1Messages[fromPIdx] = msg

	case *KGRound2Message1:
		p.temp.kgRound2Message1s[fromPIdx] = msg

	case *KGRound2Message2:
		p.temp.kgRound2Message2s[fromPIdx] = msg

	case *KGRound3Message:
		p.temp.kgRound3Messages[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

// Marshal converts LocalPartySaveData to a byte array.
func (save *LocalPartySaveData) Marshal() ([]byte, error) {
	localPreParams := &KGLocalPartySaveData_LocalPreParams{
		PaillierSK: &KGLocalPartySaveData_LocalPreParams_PrivateKey{
			PublicKey: save.LocalPreParams.PaillierSK.PublicKey.N.Bytes(),
			LambdaN:   save.LocalPreParams.PaillierSK.LambdaN.Bytes(),
			PhiN:      save.LocalPreParams.PaillierSK.PhiN.Bytes(),
		},
		NTilde: save.LocalPreParams.NTildei.Bytes(),
		H1I:    save.LocalPreParams.H1i.Bytes(),
		H2I:    save.LocalPreParams.H2i.Bytes(),
	}

	localSecrets := &KGLocalPartySaveData_LocalSecrets{
		Xi:      save.LocalSecrets.Xi.Bytes(),
		ShareID: save.LocalSecrets.ShareID.Bytes(),
	}

	marshalBigIntSlice := func(bigInts []*big.Int) [][]byte {
		bytesSlice := make([][]byte, len(bigInts))
		for i, bigInt := range bigInts {
			bytesSlice[i] = bigInt.Bytes()
		}
		return bytesSlice
	}

	bigXj := make([][]byte, len(save.BigXj))
	for i, bigX := range save.BigXj {
		encoded, err := bigX.GobEncode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode BigXj: [%v]", err)
		}
		bigXj[i] = encoded
	}

	paillierPKs := make([][]byte, len(save.PaillierPKs))
	for i, paillierPK := range save.PaillierPKs {
		paillierPKs[i] = paillierPK.N.Bytes()
	}

	ecdsaPub, err := save.ECDSAPub.GobEncode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode ECDSAPub: [%v]", err)
	}

	return proto.Marshal(&KGLocalPartySaveData{
		LocalPreParams: localPreParams,
		LocalSecrets:   localSecrets,
		Ks:             marshalBigIntSlice(save.Ks),
		NTildej:        marshalBigIntSlice(save.NTildej),
		H1J:            marshalBigIntSlice(save.H1j),
		H2J:            marshalBigIntSlice(save.H2j),
		BigXj:          bigXj,
		PaillierPKs:    paillierPKs,
		EcdsaPub:       ecdsaPub,
	})
}

// Unmarshal converts a byte array back to LocalPartySaveData.
func (save *LocalPartySaveData) Unmarshal(bytes []byte) error {
	pbData := KGLocalPartySaveData{}
	if err := pbData.XXX_Unmarshal(bytes); err != nil {
		return fmt.Errorf("failed to unmarshal signer: [%v]", err)
	}

	paillierSK := &paillier.PrivateKey{
		PublicKey: paillier.PublicKey{
			N: new(big.Int).SetBytes(pbData.GetLocalPreParams().GetPaillierSK().GetPublicKey()),
		},
		LambdaN: new(big.Int).SetBytes(pbData.GetLocalPreParams().GetPaillierSK().GetLambdaN()),
		PhiN:    new(big.Int).SetBytes(pbData.GetLocalPreParams().GetPaillierSK().GetPhiN()),
	}

	save.LocalPreParams = LocalPreParams{
		PaillierSK: paillierSK,
		NTildei:    new(big.Int).SetBytes(pbData.GetLocalPreParams().GetNTilde()),
		H1i:        new(big.Int).SetBytes(pbData.GetLocalPreParams().GetH1I()),
		H2i:        new(big.Int).SetBytes(pbData.GetLocalPreParams().GetH2I()),
	}

	save.LocalSecrets = LocalSecrets{
		Xi:      new(big.Int).SetBytes(pbData.GetLocalSecrets().GetXi()),
		ShareID: new(big.Int).SetBytes(pbData.GetLocalSecrets().GetShareID()),
	}

	unmarshalBigIntSlice := func(bytesSlice [][]byte) []*big.Int {
		bigIntSlice := make([]*big.Int, len(bytesSlice))
		for i, bytes := range bytesSlice {
			bigIntSlice[i] = new(big.Int).SetBytes(bytes)
		}
		return bigIntSlice
	}

	save.BigXj = make([]*crypto.ECPoint, len(pbData.GetBigXj()))
	for i, bigX := range pbData.GetBigXj() {
		save.BigXj[i] = &crypto.ECPoint{}
		if err := save.BigXj[i].GobDecode(bigX); err != nil {
			return fmt.Errorf("failed to decode BigXj: [%v]", err)
		}
	}

	save.PaillierPKs = make([]*paillier.PublicKey, len(pbData.GetPaillierPKs()))
	for i, paillierPK := range pbData.GetPaillierPKs() {
		save.PaillierPKs[i] = &paillier.PublicKey{
			N: new(big.Int).SetBytes(paillierPK),
		}
	}

	save.ECDSAPub = &crypto.ECPoint{}
	if err := save.ECDSAPub.GobDecode(pbData.GetEcdsaPub()); err != nil {
		return fmt.Errorf("failed to decode ECDSAPub: [%v]", err)
	}

	save.Ks = unmarshalBigIntSlice(pbData.GetKs())
	save.NTildej = unmarshalBigIntSlice(pbData.GetNTildej())
	save.H1j = unmarshalBigIntSlice(pbData.GetH1J())
	save.H2j = unmarshalBigIntSlice(pbData.GetH2J())

	return nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
