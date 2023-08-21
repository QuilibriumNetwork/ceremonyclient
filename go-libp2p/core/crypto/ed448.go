package crypto

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/internal/catch"

	"github.com/cloudflare/circl/sign/ed448"
)

// Ed448PrivateKey is an ed448 private key.
type Ed448PrivateKey struct {
	k ed448.PrivateKey
}

// Ed448PublicKey is an ed448 public key.
type Ed448PublicKey struct {
	k ed448.PublicKey
}

// GenerateEd448Key generates a new ed448 private and public key pair.
func GenerateEd448Key(src io.Reader) (PrivKey, PubKey, error) {
	pub, priv, err := ed448.GenerateKey(src)
	if err != nil {
		return nil, nil, err
	}

	return &Ed448PrivateKey{
			k: priv,
		},
		&Ed448PublicKey{
			k: pub,
		},
		nil
}

// Type of the private key (Ed448).
func (k *Ed448PrivateKey) Type() pb.KeyType {
	return pb.KeyType_Ed448
}

// Raw private key bytes.
func (k *Ed448PrivateKey) Raw() ([]byte, error) {
	// The Ed448 private key contains two 57-bytes curve points, the private
	// key and the public key.
	// It makes it more efficient to get the public key without re-computing an
	// elliptic curve multiplication.
	buf := make([]byte, len(k.k))
	copy(buf, k.k)

	return buf, nil
}

func (k *Ed448PrivateKey) pubKeyBytes() []byte {
	return k.k[ed448.PrivateKeySize-ed448.PublicKeySize:]
}

// Equals compares two ed448 private keys.
func (k *Ed448PrivateKey) Equals(o Key) bool {
	edk, ok := o.(*Ed448PrivateKey)
	if !ok {
		return basicEquals(k, o)
	}

	return subtle.ConstantTimeCompare(k.k, edk.k) == 1
}

// GetPublic returns an ed448 public key from a private key.
func (k *Ed448PrivateKey) GetPublic() PubKey {
	return &Ed448PublicKey{k: k.pubKeyBytes()}
}

// Sign returns a signature from an input message.
func (k *Ed448PrivateKey) Sign(msg []byte) (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "ed448 signing") }()

	return ed448.Sign(k.k, msg, ""), nil
}

// Type of the public key (Ed448).
func (k *Ed448PublicKey) Type() pb.KeyType {
	return pb.KeyType_Ed448
}

// Raw public key bytes.
func (k *Ed448PublicKey) Raw() ([]byte, error) {
	return k.k, nil
}

// Equals compares two ed448 public keys.
func (k *Ed448PublicKey) Equals(o Key) bool {
	edk, ok := o.(*Ed448PublicKey)
	if !ok {
		return basicEquals(k, o)
	}

	return bytes.Equal(k.k, edk.k)
}

// Verify checks a signature against the input data.
func (k *Ed448PublicKey) Verify(data []byte, sig []byte) (success bool, err error) {
	defer func() {
		catch.HandlePanic(recover(), &err, "ed448 signature verification")

		// To be safe.
		if err != nil {
			success = false
		}
	}()
	return ed448.Verify(k.k, data, sig, ""), nil
}

// UnmarshalEd448PublicKey returns a public key from input bytes.
func UnmarshalEd448PublicKey(data []byte) (PubKey, error) {
	if len(data) != 57 {
		return nil, errors.New("expect ed448 public key data size to be 57")
	}

	return &Ed448PublicKey{
		k: ed448.PublicKey(data),
	}, nil
}

// UnmarshalEd448PrivateKey returns a private key from input bytes.
func UnmarshalEd448PrivateKey(data []byte) (PrivKey, error) {
	switch len(data) {
	case ed448.PrivateKeySize + ed448.PublicKeySize:
		// Remove the redundant public key. See issue #36.
		redundantPk := data[ed448.PrivateKeySize:]
		pk := data[ed448.PrivateKeySize-ed448.PublicKeySize : ed448.PrivateKeySize]
		if subtle.ConstantTimeCompare(pk, redundantPk) == 0 {
			return nil, errors.New("expected redundant ed448 public key to be redundant")
		}

		// No point in storing the extra data.
		newKey := make([]byte, ed448.PrivateKeySize)
		copy(newKey, data[:ed448.PrivateKeySize])
		data = newKey
	case ed448.PrivateKeySize:
	default:
		return nil, fmt.Errorf(
			"expected ed448 data size to be %d or %d, got %d",
			ed448.PrivateKeySize,
			ed448.PrivateKeySize+ed448.PublicKeySize,
			len(data),
		)
	}

	return &Ed448PrivateKey{
		k: ed448.PrivateKey(data),
	}, nil
}
