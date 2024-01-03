package keys

import (
	"crypto"
	"crypto/rand"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

type InMemoryKeyManager struct {
	key   ByteString
	store map[string]Key
}

func NewInMemoryKeyManager() *InMemoryKeyManager {
	store := make(map[string]Key)

	return &InMemoryKeyManager{
		store: store,
	}
}

// CreateSigningKey implements KeyManager
func (f *InMemoryKeyManager) CreateSigningKey(
	id string,
	keyType KeyType,
) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeEd448:
		pubkey, privkey, err := ed448.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "could not generate key")
		}

		if err = f.save(
			id,
			Key{
				Id:         id,
				Type:       keyType,
				PublicKey:  ByteString(pubkey),
				PrivateKey: ByteString(privkey),
			},
		); err != nil {
			return nil, errors.Wrap(err, "could not save")
		}

		return privkey, nil
		// case KeyTypePCAS:
		// 	_, privkey, err := addressing.GenerateKey(rand.Reader)
		// 	if err != nil {
		// 		return nil, errors.Wrap(err, "could not generate key")
		// 	}

		// 	if err = f.save(id, privkey); err != nil {
		// 		return nil, errors.Wrap(err, "could not save")
		// 	}

		// 	return privkey, nil
	}

	return nil, UnsupportedKeyTypeErr
}

// CreateAgreementKey implements KeyManager
func (f *InMemoryKeyManager) CreateAgreementKey(
	id string,
	keyType KeyType,
) (curves.Scalar, error) {
	switch keyType {
	case KeyTypeX448:
		privkey := curves.ED448().Scalar.Random(rand.Reader)
		pubkey := curves.ED448().NewGeneratorPoint().Mul(privkey)

		if err := f.save(
			id,
			Key{
				Id:         id,
				Type:       KeyTypeX448,
				PublicKey:  pubkey.ToAffineCompressed(),
				PrivateKey: privkey.Bytes(),
			},
		); err != nil {
			return nil, errors.Wrap(err, "could not save")
		}

		return privkey, nil
	}

	return nil, UnsupportedKeyTypeErr
}

// GetAgreementKey implements KeyManager
func (f *InMemoryKeyManager) GetAgreementKey(id string) (curves.Scalar, error) {
	key, err := f.read(id)
	if err != nil {
		return nil, err
	}

	switch key.Type {
	case KeyTypeX448:
		privkey, err := curves.ED448().NewScalar().SetBytes(key.PrivateKey)
		return privkey, err
	}

	return nil, UnsupportedKeyTypeErr
}

// GetRawKey implements KeyManager
func (f *InMemoryKeyManager) GetRawKey(id string) (*Key, error) {
	key, err := f.read(id)
	return &key, err
}

// GetSigningKey implements KeyManager
func (f *InMemoryKeyManager) GetSigningKey(id string) (crypto.Signer, error) {
	key, err := f.read(id)
	if err != nil {
		return nil, err
	}

	switch key.Type {
	case KeyTypeEd448:
		privkey := (ed448.PrivateKey)(key.PrivateKey)
		return privkey, err
		// case KeyTypePCAS:
		// 	privkey := (addressing.PCAS)(key.PrivateKey)
		// 	return privkey, err
	}

	return nil, UnsupportedKeyTypeErr
}

// PutRawKey implements KeyManager
func (f *InMemoryKeyManager) PutRawKey(key *Key) error {
	return f.save(key.Id, *key)
}

// DeleteKey implements KeyManager
func (f *InMemoryKeyManager) DeleteKey(id string) error {
	delete(f.store, id)

	return nil
}

// GetKey implements KeyManager
func (f *InMemoryKeyManager) GetKey(id string) (key *Key, err error) {
	storeKey, err := f.read(id)
	if err != nil {
		return nil, err
	}

	return &storeKey, nil
}

// ListKeys implements KeyManager
func (f *InMemoryKeyManager) ListKeys() ([]*Key, error) {
	keys := []*Key{}

	for k := range f.store {
		storeKey, err := f.read(k)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &storeKey)
	}

	return keys, nil
}

var _ KeyManager = (*InMemoryKeyManager)(nil)

func (f *InMemoryKeyManager) save(id string, key Key) error {
	f.store[id] = Key{
		Id:         key.Id,
		Type:       key.Type,
		PublicKey:  key.PublicKey,
		PrivateKey: key.PrivateKey,
	}

	return nil
}

func (f *InMemoryKeyManager) read(id string) (Key, error) {
	k, ok := f.store[id]
	if !ok {
		return Key{}, KeyNotFoundErr
	}

	return Key{
		Id:         k.Id,
		Type:       k.Type,
		PublicKey:  k.PublicKey,
		PrivateKey: k.PrivateKey,
	}, nil
}
