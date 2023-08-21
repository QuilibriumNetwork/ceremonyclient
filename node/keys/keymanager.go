package keys

import (
	"crypto"
	"encoding/hex"
	"errors"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

type KeyType int

const (
	KeyTypeEd448 = iota
	KeyTypeX448
	KeyTypeBLS48581G1
	KeyTypeBLS48581G2
	KeyTypePCAS
)

type KeyManager interface {
	GetRawKey(id string) (*Key, error)
	GetSigningKey(id string) (crypto.Signer, error)
	GetAgreementKey(id string) (curves.Scalar, error)
	PutRawKey(key *Key) error
	CreateSigningKey(id string, keyType KeyType) (crypto.Signer, error)
	CreateAgreementKey(id string, keyType KeyType) (curves.Scalar, error)
	DeleteKey(id string) error
	ListKeys() ([]*Key, error)
}

type ByteString []byte

func (b ByteString) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(b)), nil
}

func (b *ByteString) UnmarshalText(text []byte) error {
	value, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}

	*b = value
	return nil
}

type Key struct {
	Id         string     `yaml:"id"`
	Type       KeyType    `yaml:"type"`
	PrivateKey ByteString `yaml:"privateKey"`
	PublicKey  ByteString `yaml:"publicKey"`
}

func MapCurveToKeyType(curve curves.Curve, agreement bool) (KeyType, error) {
	switch curve.Name {
	case curves.ED448Name:
		if agreement {
			return KeyTypeEd448, nil
		} else {
			return KeyTypeX448, nil
		}
	case curves.BLS48581G1Name:
		return KeyTypeBLS48581G1, nil
	case curves.BLS48581G2Name:
		return KeyTypeBLS48581G2, nil
	}

	return KeyTypeEd448, errors.New("no keytype for curve")
}
