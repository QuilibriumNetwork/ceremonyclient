package application

import (
	"encoding/binary"
	"encoding/json"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	bls48581 "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ot/base/simplest"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ot/extension/kos"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/tecdsa/dkls/v1/sign"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/zkp/schnorr"
)

type MultiplyReceiverRound int
type MultiplySenderRound int

const (
	MULTIPLY_RECEIVER_ROUND_UNINITIALIZED = MultiplyReceiverRound(iota)
	MULTIPLY_RECEIVER_ROUND_1_COMPUTE_AND_ZKP_TO_PUBKEY
	MULTIPLY_RECEIVER_ROUND_2_PAD_TRANSFER
	MULTIPLY_RECEIVER_ROUND_3_VERIFY
	MULTIPLY_RECEIVER_ROUND_4_MULTIPLY_INIT
	MULTIPLY_RECEIVER_ROUND_5_MULTIPLY
	MULTIPLY_RECEIVER_ROUND_6_DONE
)

const (
	MULTIPLY_SENDER_ROUND_UNINITIALIZED = MultiplySenderRound(iota)
	MULTIPLY_SENDER_ROUND_1_INITIALIZED
	MULTIPLY_SENDER_ROUND_2_VERIFY_SCHNORR_AND_PAD_TRANSFER
	MULTIPLY_SENDER_ROUND_3_RESPOND_TO_CHALLENGE
	MULTIPLY_SENDER_ROUND_4_VERIFY
	MULTIPLY_SENDER_ROUND_5_MULTIPLY
	MULTIPLY_SENDER_ROUND_6_DONE
)

type Iterator interface {
	Init() error
	Next(message []byte) ([]byte, error)
	IsDone() bool
	GetPoints() []curves.Point
	GetScalars() []curves.Scalar
}

type MultiplySender struct {
	seed             [32]byte
	alphas           []curves.Scalar
	curve            *curves.Curve
	simplestReceiver *simplest.Receiver
	sender           []*sign.MultiplySender
	step             MultiplySenderRound
}

type MultiplyReceiver struct {
	seed           [32]byte
	betas          []curves.Scalar
	curve          *curves.Curve
	simplestSender *simplest.Sender
	receiver       []*sign.MultiplyReceiver
	step           MultiplyReceiverRound
}

var _ Iterator = (*MultiplySender)(nil)
var _ Iterator = (*MultiplyReceiver)(nil)

type SchnorrProof struct {
	C         []byte
	S         []byte
	Statement []byte
}

type KOSRound2Output struct {
	Tau [][][]byte
}

type MultiplyRound2Output struct {
	COTRound2Output *KOSRound2Output
	R               [][]byte
	U               []byte
}

func NewMultiplySender(
	alphas []curves.Scalar,
	curve *curves.Curve,
	seed [32]byte,
) *MultiplySender {
	return &MultiplySender{
		seed:             seed,
		alphas:           alphas,
		curve:            curve,
		simplestReceiver: nil,
		sender:           []*sign.MultiplySender{},
		step:             MULTIPLY_SENDER_ROUND_UNINITIALIZED,
	}
}

func NewMultiplyReceiver(
	betas []curves.Scalar,
	curve *curves.Curve,
	seed [32]byte,
) *MultiplyReceiver {
	return &MultiplyReceiver{
		seed:           seed,
		betas:          betas,
		curve:          curve,
		simplestSender: nil,
		receiver:       []*sign.MultiplyReceiver{},
		step:           MULTIPLY_RECEIVER_ROUND_UNINITIALIZED,
	}
}

func (s *MultiplySender) Init() error {
	seed := sha3.Sum256(append(append([]byte{}, s.seed[:]...), []byte("OT")...))
	var err error
	s.simplestReceiver, err = simplest.NewReceiver(s.curve, 584, seed)
	s.step = MULTIPLY_SENDER_ROUND_1_INITIALIZED
	return err
}

func (r *MultiplyReceiver) Init() error {
	seed := sha3.Sum256(append(append([]byte{}, r.seed[:]...), []byte("OT")...))
	var err error
	r.simplestSender, err = simplest.NewSender(r.curve, 584, seed)
	r.step = MULTIPLY_RECEIVER_ROUND_1_COMPUTE_AND_ZKP_TO_PUBKEY
	return err
}

func (s *MultiplySender) Next(message []byte) ([]byte, error) {
	switch s.step {
	case MULTIPLY_SENDER_ROUND_1_INITIALIZED:
		s.step = MULTIPLY_SENDER_ROUND_2_VERIFY_SCHNORR_AND_PAD_TRANSFER
		return nil, nil
	case MULTIPLY_SENDER_ROUND_2_VERIFY_SCHNORR_AND_PAD_TRANSFER:
		proof := &SchnorrProof{}
		err := json.Unmarshal([]byte(message), proof)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		schnorrC, err := s.curve.Scalar.SetBytes(proof.C)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		schnorrS, err := s.curve.Scalar.SetBytes(proof.S)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		schnorrStatement, err := s.curve.Point.FromAffineCompressed(proof.Statement)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		schnorrProof := &schnorr.Proof{
			C:         schnorrC,
			S:         schnorrS,
			Statement: schnorrStatement,
		}

		receiversMaskedChoice, err :=
			s.simplestReceiver.Round2VerifySchnorrAndPadTransfer(schnorrProof)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		marshaledReceiversMaskedChoice, err := json.Marshal(receiversMaskedChoice)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		s.step = MULTIPLY_SENDER_ROUND_3_RESPOND_TO_CHALLENGE
		return marshaledReceiversMaskedChoice, nil
	case MULTIPLY_SENDER_ROUND_3_RESPOND_TO_CHALLENGE:
		challenge := [][32]byte{}
		err := json.Unmarshal([]byte(message), &challenge)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		challengeResponse, err := s.simplestReceiver.Round4RespondToChallenge(
			challenge,
		)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		marshaledChallengeResponse, err := json.Marshal(challengeResponse)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		s.step = MULTIPLY_SENDER_ROUND_4_VERIFY
		return marshaledChallengeResponse, errors.Wrap(err, "next")
	case MULTIPLY_SENDER_ROUND_4_VERIFY:
		challengeOpenings := [][2][32]byte{}
		err := json.Unmarshal([]byte(message), &challengeOpenings)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		err = s.simplestReceiver.Round6Verify(challengeOpenings)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		baseOtReceiverOutput := s.simplestReceiver.Output

		for i := 0; i < len(s.alphas); i++ {
			seed := sha3.Sum256(
				append(
					append(
						append([]byte{}, s.seed[:]...),
						[]byte("MUL")...,
					),
					binary.BigEndian.AppendUint64([]byte{}, uint64(i))...,
				),
			)
			sender, err := sign.NewMultiplySender(
				584,
				160,
				baseOtReceiverOutput,
				s.curve,
				seed,
			)
			if err != nil {
				return nil, errors.Wrap(err, "next")
			}
			s.sender = append(s.sender, sender)
		}

		s.step = MULTIPLY_SENDER_ROUND_5_MULTIPLY
		return nil, nil
	case MULTIPLY_SENDER_ROUND_5_MULTIPLY:
		round1Outputs := []*kos.Round1Output{}
		err := json.Unmarshal([]byte(message), &round1Outputs)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		if len(round1Outputs) != len(s.alphas) {
			return nil, errors.Wrap(errors.New("incorrect number of outputs"), "next")
		}

		outputs := []*MultiplyRound2Output{}

		for i := 0; i < len(s.alphas); i++ {
			round2Output, err := s.sender[i].Round2Multiply(
				s.alphas[i],
				round1Outputs[i],
			)
			if err != nil {
				return nil, errors.Wrap(err, "next")
			}

			tau := [][][]byte{}
			for _, t := range round2Output.COTRound2Output.Tau {
				tBytes := [][]byte{}
				for _, ts := range t {
					tBytes = append(tBytes, ts.Bytes())
				}
				tau = append(tau, tBytes)
			}

			r := [][]byte{}
			for _, rs := range round2Output.R {
				r = append(r, rs.Bytes())
			}

			outputs = append(outputs, &MultiplyRound2Output{
				COTRound2Output: &KOSRound2Output{
					Tau: tau,
				},
				R: r,
				U: round2Output.U.Bytes(),
			})
		}

		marshaledOutputs, err := json.Marshal(outputs)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		s.step = MULTIPLY_SENDER_ROUND_6_DONE
		return marshaledOutputs, nil
	}

	return nil, nil
}

func (r *MultiplyReceiver) Next(message []byte) ([]byte, error) {
	switch r.step {
	case MULTIPLY_RECEIVER_ROUND_1_COMPUTE_AND_ZKP_TO_PUBKEY:
		proof, err := r.simplestSender.Round1ComputeAndZkpToPublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		schnorrProof := &SchnorrProof{
			C:         proof.C.Bytes(),
			S:         proof.S.Bytes(),
			Statement: proof.Statement.ToAffineCompressed(),
		}

		marshaledProof, err := json.Marshal(schnorrProof)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		r.step = MULTIPLY_RECEIVER_ROUND_2_PAD_TRANSFER
		return marshaledProof, nil
	case MULTIPLY_RECEIVER_ROUND_2_PAD_TRANSFER:
		receiversMaskedChoice := [][]byte{}
		err := json.Unmarshal([]byte(message), &receiversMaskedChoice)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		challenge, err := r.simplestSender.Round3PadTransfer(receiversMaskedChoice)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		marshaledChallenge, err := json.Marshal(challenge)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		r.step = MULTIPLY_RECEIVER_ROUND_3_VERIFY
		return marshaledChallenge, nil
	case MULTIPLY_RECEIVER_ROUND_3_VERIFY:
		challengeResponse := [][32]byte{}
		err := json.Unmarshal([]byte(message), &challengeResponse)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		challengeOpenings, err := r.simplestSender.Round5Verify(challengeResponse)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		marshaledChallengeOpenings, err := json.Marshal(challengeOpenings)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		r.step = MULTIPLY_RECEIVER_ROUND_4_MULTIPLY_INIT

		return marshaledChallengeOpenings, nil
	case MULTIPLY_RECEIVER_ROUND_4_MULTIPLY_INIT:
		baseOtSenderOutput := r.simplestSender.Output
		outputs := []*kos.Round1Output{}

		for i := 0; i < len(r.betas); i++ {
			seed := sha3.Sum256(
				append(
					append(
						append([]byte{}, r.seed[:]...),
						[]byte("MUL")...,
					),
					binary.BigEndian.AppendUint64([]byte{}, uint64(i))...,
				),
			)
			receiver, err := sign.NewMultiplyReceiver(
				584,
				160,
				baseOtSenderOutput,
				r.curve,
				seed,
			)
			if err != nil {
				return nil, errors.Wrap(err, "next")
			}
			r.receiver = append(r.receiver, receiver)
			round1Output, err := r.receiver[i].Round1Initialize(r.betas[i])
			if err != nil {
				return nil, errors.Wrap(err, "next")
			}

			outputs = append(outputs, round1Output)
		}

		marshaledOutputs, err := json.Marshal(outputs)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		r.step = MULTIPLY_RECEIVER_ROUND_5_MULTIPLY
		return marshaledOutputs, nil
	case MULTIPLY_RECEIVER_ROUND_5_MULTIPLY:
		round2Output := []*MultiplyRound2Output{}
		err := json.Unmarshal([]byte(message), &round2Output)
		if err != nil {
			return nil, errors.Wrap(err, "next")
		}

		if len(round2Output) != len(r.betas) {
			return nil, errors.Wrap(errors.New("incorrect number of outputs"), "next")
		}

		for i := 0; i < len(r.betas); i++ {
			rawRound2Output := &sign.MultiplyRound2Output{
				COTRound2Output: &kos.Round2Output{
					Tau: [][]curves.Scalar{},
				},
				R: []curves.Scalar{},
				U: nil,
			}

			for _, t := range round2Output[i].COTRound2Output.Tau {
				tScalars := []curves.Scalar{}
				for _, ts := range t {
					sc, err := r.curve.Scalar.SetBytes(ts)
					if err != nil {
						return nil, errors.Wrap(err, "next")
					}

					tScalars = append(tScalars, sc)
				}
				rawRound2Output.COTRound2Output.Tau = append(
					rawRound2Output.COTRound2Output.Tau,
					tScalars,
				)
			}

			for _, rs := range round2Output[i].R {
				sc, err := r.curve.Scalar.SetBytes(rs)
				if err != nil {
					return nil, errors.Wrap(err, "next")
				}
				rawRound2Output.R = append(rawRound2Output.R, sc)
			}

			rawRound2Output.U, err = r.curve.Scalar.SetBytes(round2Output[i].U)
			if err != nil {
				return nil, errors.Wrap(err, "next")
			}

			err := r.receiver[i].Round3Multiply(rawRound2Output)
			if err != nil {
				return nil, errors.Wrap(err, "next")
			}
		}

		r.step = MULTIPLY_RECEIVER_ROUND_6_DONE
		return nil, nil
	}
	return nil, nil
}

func (s *MultiplySender) IsDone() bool {
	return s.step == MULTIPLY_SENDER_ROUND_6_DONE
}

func (r *MultiplyReceiver) IsDone() bool {
	return r.step == MULTIPLY_RECEIVER_ROUND_6_DONE
}

func (s *MultiplySender) GetPoints() []curves.Point {
	points := []curves.Point{}

	for i := 0; i < len(s.alphas); i++ {
		points = append(
			points,
			s.curve.NewGeneratorPoint().Mul(
				s.sender[i].OutputAdditiveShare,
			),
		)
	}

	return points
}

func (r *MultiplyReceiver) GetPoints() []curves.Point {
	points := []curves.Point{}

	for i := 0; i < len(r.betas); i++ {
		points = append(
			points,
			r.curve.NewGeneratorPoint().Mul(
				r.receiver[i].OutputAdditiveShare,
			),
		)
	}

	return points
}

func (s *MultiplySender) GetScalars() []curves.Scalar {
	scalars := []curves.Scalar{}

	for i := 0; i < len(s.alphas); i++ {
		scalars = append(
			scalars,
			s.sender[i].OutputAdditiveShare,
		)
	}

	return scalars
}

func (r *MultiplyReceiver) GetScalars() []curves.Scalar {
	scalars := []curves.Scalar{}

	for i := 0; i < len(r.betas); i++ {
		scalars = append(
			scalars,
			r.receiver[i].OutputAdditiveShare,
		)
	}

	return scalars
}

func (s *MultiplySender) GetSignatureOfProverKey(
	proverKey []byte,
) ([]byte, error) {
	signature := make([]byte, int(bls48581.MODBYTES)+1)
	key := s.sender[0].OutputAdditiveShare.Bytes()

	if bls48581.Core_Sign(signature, proverKey, key) != bls48581.BLS_OK {
		return nil, errors.Wrap(
			errors.New("could not sign"),
			"get signature of prover key",
		)
	}

	return signature[:], nil
}

func (r *MultiplyReceiver) GetSignatureOfProverKey(
	proverKey []byte,
) ([]byte, error) {
	signature := make([]byte, int(bls48581.MODBYTES)+1)
	key := r.receiver[0].OutputAdditiveShare.Bytes()

	if bls48581.Core_Sign(signature, proverKey, key) != bls48581.BLS_OK {
		return nil, errors.Wrap(
			errors.New("could not sign"),
			"get signature of prover key",
		)
	}

	return signature[:], nil
}

func SignProverKeyForCommit(
	proverKey []byte,
	commitKey curves.Scalar,
) ([]byte, error) {
	signature := make([]byte, int(bls48581.MODBYTES)+1)
	key := commitKey.Bytes()

	if bls48581.Core_Sign(signature, proverKey, key) != bls48581.BLS_OK {
		return nil, errors.Wrap(
			errors.New("could not sign"),
			"sign prover key for commit",
		)
	}

	return signature[:], nil
}

func VerifySignatureOfProverKey(
	proverKey []byte,
	signature []byte,
	publicPointG2 curves.Point,
) error {
	w := publicPointG2.ToAffineCompressed()

	if bls48581.Core_Verify(signature, proverKey, w) != bls48581.BLS_OK {
		return errors.Wrap(
			errors.New("could not verify"),
			"verify signature of prover key",
		)
	}

	return nil
}
