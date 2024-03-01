package protobufs

import (
	"crypto"
	"crypto/rand"
	"encoding/binary"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

func (j *CeremonyLobbyJoin) VerifySignature() error {
	b := binary.BigEndian.AppendUint64([]byte("join"), j.FrameNumber)
	b = append(b, j.IdentityKey.KeyValue...)
	b = append(b, j.SignedPreKey.KeyValue...)
	b = append(b, j.PeerId...)

	if !ed448.Verify(
		j.PublicKeySignatureEd448.PublicKey.KeyValue,
		b,
		j.PublicKeySignatureEd448.Signature,
		"",
	) {
		return errors.Wrap(errors.New("invalid signature"), "sign with prover key")
	}

	return nil
}

func (j *CeremonyLobbyJoin) SignWithProverKey(
	signer crypto.Signer,
) ([]byte, error) {
	b := binary.BigEndian.AppendUint64([]byte("join"), j.FrameNumber)
	b = append(b, j.IdentityKey.KeyValue...)
	b = append(b, j.SignedPreKey.KeyValue...)
	b = append(b, j.PeerId...)

	// Non edwards signing variants need support to specify hash, edwards variants
	// demand Hash(0) because it does SHA512 under the hood.
	sig, err := signer.Sign(rand.Reader, b, crypto.Hash(0))
	return sig, errors.Wrap(err, "sign with prover key")
}

func (t *CeremonyTranscriptShare) VerifySignature() error {
	hash := sha3.New256()

	for _, g1 := range t.AdditiveG1Powers {
		if _, err := hash.Write(g1.KeyValue); err != nil {
			return errors.Wrap(err, "verify signature")
		}
	}

	for _, g2 := range t.AdditiveG2Powers {
		if _, err := hash.Write(g2.KeyValue); err != nil {
			return errors.Wrap(err, "verify signature")
		}
	}

	if _, err := hash.Write(t.AdditiveG1_256Witness.KeyValue); err != nil {
		return errors.Wrap(err, "verify signature")
	}

	return errors.Wrap(
		t.ProverSignature.Verify(hash.Sum(nil)),
		"verify signature",
	)
}

func (t *CeremonyTranscriptShare) SignWithProverKey(
	signer crypto.Signer,
) ([]byte, error) {
	hash := sha3.New256()

	for _, g1 := range t.AdditiveG1Powers {
		if _, err := hash.Write(g1.KeyValue); err != nil {
			return nil, errors.Wrap(err, "sign with prover key")
		}
	}

	for _, g2 := range t.AdditiveG2Powers {
		if _, err := hash.Write(g2.KeyValue); err != nil {
			return nil, errors.Wrap(err, "sign with prover key")
		}
	}

	if _, err := hash.Write(t.AdditiveG1_256Witness.KeyValue); err != nil {
		return nil, errors.Wrap(err, "sign with prover key")
	}

	signature, err := signer.Sign(rand.Reader, hash.Sum(nil), crypto.Hash(0))
	return signature, errors.Wrap(err, "sign with prover key")
}
