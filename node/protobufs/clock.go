package protobufs

import (
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/vdf"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
)

func ProveMasterClockFrame(
	previousFrame *ClockFrame,
	difficulty uint32,
) (*ClockFrame, error) {
	input := []byte{}
	input = append(input, previousFrame.Filter...)
	input = binary.BigEndian.AppendUint64(input, previousFrame.FrameNumber+1)
	input = binary.BigEndian.AppendUint32(input, difficulty)
	input = append(input, previousFrame.Output[:]...)

	b := sha3.Sum256(input)
	v := vdf.New(difficulty, b)
	v.Execute()
	o := v.GetOutput()

	timestamp := time.Now().UnixMilli()

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], previousFrame.Output[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "prove clock frame")
	}

	frame := &ClockFrame{
		Filter:          previousFrame.Filter,
		FrameNumber:     previousFrame.FrameNumber + 1,
		Timestamp:       timestamp,
		Difficulty:      difficulty,
		ParentSelector:  parent.Bytes(),
		Input:           previousFrame.Output,
		AggregateProofs: []*InclusionAggregateProof{},
		Output:          o[:],
	}

	return frame, nil
}

func (frame *ClockFrame) VerifyMasterClockFrame() error {
	input := []byte{}
	input = append(input, frame.Filter...)
	input = binary.BigEndian.AppendUint64(input, frame.FrameNumber)
	input = binary.BigEndian.AppendUint32(input, frame.Difficulty)
	input = append(input, frame.Input...)

	if len(frame.Input) < 516 {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	if len(frame.AggregateProofs) > 0 {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	if frame.PublicKeySignature != nil {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	if len(frame.Input) != 516 {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	b := sha3.Sum256(input)
	v := vdf.New(frame.Difficulty, b)
	proof := [516]byte{}
	copy(proof[:], frame.Output)

	if !v.Verify(proof) {
		return errors.Wrap(
			errors.New("invalid proof"),
			"verify clock frame",
		)
	}

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return errors.Wrap(err, "verify clock frame")
	}

	selector := new(big.Int).SetBytes(frame.ParentSelector)
	if parent.Cmp(selector) != 0 {
		return errors.Wrap(
			errors.New("selector did not match input"),
			"verify clock frame",
		)
	}

	return nil
}

func (frame *ClockFrame) GetParentSelectorAndDistance() (
	*big.Int,
	*big.Int,
	*big.Int,
	error,
) {
	outputBytes := [516]byte{}
	copy(outputBytes[:], frame.Output[:516])

	selector, err := poseidon.HashBytes(outputBytes[:])
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "get parent selector and distance")
	}

	if frame.FrameNumber == 0 {
		return big.NewInt(0), big.NewInt(0), selector, nil
	}

	parentSelector := new(big.Int).SetBytes(frame.ParentSelector)

	var pubkey []byte
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
	} else {
		return nil, nil, nil, errors.Wrap(
			errors.New("no valid signature provided"),
			"get parent selector and distance",
		)
	}

	discriminator, err := poseidon.HashBytes(pubkey)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "get parent selector and distance")
	}

	l := new(big.Int).Mod(new(big.Int).Sub(selector, discriminator), ff.Modulus())
	r := new(big.Int).Mod(new(big.Int).Sub(discriminator, selector), ff.Modulus())
	distance := r
	if l.Cmp(r) == -1 {
		distance = l
	}

	return parentSelector, distance, selector, nil
}

func (frame *ClockFrame) GetSelector() (*big.Int, error) {
	outputBytes := [516]byte{}
	copy(outputBytes[:], frame.Output[:516])

	selector, err := poseidon.HashBytes(outputBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "get selector")
	}

	return selector, nil
}

func (frame *ClockFrame) GetPublicKey() ([]byte, error) {
	if frame.FrameNumber == 0 {
		return make([]byte, 32), nil
	}
	var pubkey []byte
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
	} else {
		return nil, errors.Wrap(
			errors.New("no valid signature provided"),
			"get address",
		)
	}

	return pubkey, nil
}

func (frame *ClockFrame) GetAddress() ([]byte, error) {
	if frame.FrameNumber == 0 {
		return make([]byte, 32), nil
	}
	var pubkey []byte
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
	} else {
		return nil, errors.Wrap(
			errors.New("no valid signature provided"),
			"get address",
		)
	}

	address, err := poseidon.HashBytes(pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "get parent selector and distance")
	}
	addressBytes := address.Bytes()
	addressBytes = append(make([]byte, 32-len(addressBytes)), addressBytes...)

	return addressBytes, nil
}

func ProveDataClockFrame(
	previousFrame *ClockFrame,
	commitments [][]byte,
	aggregateProofs []*InclusionAggregateProof,
	provingKey crypto.Signer,
	difficulty uint32,
) (*ClockFrame, error) {
	var pubkey []byte
	pubkeyType := keys.KeyTypeEd448
	ed448PublicKey, ok := provingKey.Public().(ed448.PublicKey)
	if ok {
		pubkey = []byte(ed448PublicKey)
	} else {
		return nil, errors.Wrap(
			errors.New("no valid signature provided"),
			"prove clock frame",
		)
	}

	h, err := poseidon.HashBytes(pubkey)
	if err != nil {
		return nil, errors.Wrap(
			errors.New("could not hash proving key"),
			"prove clock frame",
		)
	}

	address := h.Bytes()
	timestamp := time.Now().UnixMilli()
	input := []byte{}
	input = append(input, previousFrame.Filter...)
	input = binary.BigEndian.AppendUint64(input, previousFrame.FrameNumber+1)
	input = binary.BigEndian.AppendUint64(input, uint64(timestamp))
	input = binary.BigEndian.AppendUint32(input, difficulty)
	input = append(input, address...)
	input = append(input, previousFrame.Output[:]...)

	commitmentInput := []byte{}
	for _, commitment := range commitments {
		commitmentInput = append(commitmentInput, commitment...)
	}

	input = append(input, commitmentInput...)

	b := sha3.Sum256(input)
	v := vdf.New(difficulty, b)

	v.Execute()
	o := v.GetOutput()

	// TODO: make this configurable for signing algorithms that allow
	// user-supplied hash functions
	signature, err := provingKey.Sign(
		rand.Reader,
		append(append([]byte{}, b[:]...), o[:]...),
		crypto.Hash(0),
	)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"prove",
		)
	}

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], previousFrame.Output[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "prove clock frame")
	}

	frame := &ClockFrame{
		Filter:         previousFrame.Filter,
		FrameNumber:    previousFrame.FrameNumber + 1,
		Timestamp:      timestamp,
		Difficulty:     difficulty,
		ParentSelector: parent.Bytes(),
		Input: append(
			append([]byte{}, previousFrame.Output...),
			commitmentInput...,
		),
		AggregateProofs: aggregateProofs,
		Output:          o[:],
	}

	switch pubkeyType {
	case keys.KeyTypeEd448:
		frame.PublicKeySignature = &ClockFrame_PublicKeySignatureEd448{
			PublicKeySignatureEd448: &Ed448Signature{
				Signature: signature,
				PublicKey: &Ed448PublicKey{
					KeyValue: pubkey,
				},
			},
		}
	default:
		return nil, errors.Wrap(
			errors.New("unsupported proving key"),
			"prove clock frame",
		)
	}

	return frame, nil
}

func (frame *ClockFrame) VerifyDataClockFrame() error {
	var pubkey []byte
	var signature []byte
	pubkeyType := keys.KeyTypeEd448
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
		signature = ed448PublicKey.Signature
	} else {
		return errors.Wrap(
			errors.New("no valid signature provided"),
			"verify clock frame",
		)
	}

	h, err := poseidon.HashBytes(pubkey)
	if err != nil {
		return errors.Wrap(
			errors.New("could not hash proving key"),
			"verify clock frame",
		)
	}

	address := h.Bytes()

	input := []byte{}
	input = append(input, frame.Filter...)
	input = binary.BigEndian.AppendUint64(input, frame.FrameNumber)
	input = binary.BigEndian.AppendUint64(input, uint64(frame.Timestamp))
	input = binary.BigEndian.AppendUint32(input, frame.Difficulty)
	input = append(input, address...)
	input = append(input, frame.Input...)

	if len(frame.Input) < 516 {
		return errors.Wrap(
			errors.New("invalid input"),
			"verify clock frame",
		)
	}

	b := sha3.Sum256(input)
	v := vdf.New(frame.Difficulty, b)
	proof := [516]byte{}
	copy(proof[:], frame.Output)

	// TODO: make this configurable for signing algorithms that allow
	// user-supplied hash functions
	switch pubkeyType {
	case keys.KeyTypeEd448:
		if len(pubkey) != 57 || len(signature) != 114 || !ed448.VerifyAny(
			pubkey,
			append(append([]byte{}, b[:]...), frame.Output...),
			signature,
			crypto.Hash(0),
		) {
			return errors.Wrap(
				errors.New("invalid signature for issuer"),
				"verify clock frame",
			)
		}
	}
	if !v.Verify(proof) {
		return errors.Wrap(
			errors.New("invalid proof"),
			"verify clock frame",
		)
	}

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return errors.Wrap(err, "verify clock frame")
	}

	selector := new(big.Int).SetBytes(frame.ParentSelector)
	if parent.Cmp(selector) != 0 {
		return errors.Wrap(
			errors.New("selector did not match input"),
			"verify clock frame",
		)
	}

	return nil
}
