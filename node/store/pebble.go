package store

import (
	"github.com/cockroachdb/pebble"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

func NewPebbleDB(config *config.DBConfig) *pebble.DB {
	db, err := pebble.Open(config.Path, &pebble.Options{})
	if err != nil {
		panic(err)
	}

	return db
}

type Transaction interface {
	Set(key []byte, value []byte) error
	Commit() error
	Delete(key []byte) error
}

type PebbleTransaction struct {
	b *pebble.Batch
}

func (t *PebbleTransaction) Set(key []byte, value []byte) error {
	return t.b.Set(key, value, &pebble.WriteOptions{Sync: true})
}

func (t *PebbleTransaction) Commit() error {
	return t.b.Commit(&pebble.WriteOptions{Sync: true})
}

func (t *PebbleTransaction) Delete(key []byte) error {
	return t.b.Delete(key, &pebble.WriteOptions{Sync: true})
}

var _ Transaction = (*PebbleTransaction)(nil)

func rightAlign(data []byte, size int) []byte {
	l := len(data)

	if l == size {
		return data
	}

	if l > size {
		return data[l-size:]
	}

	pad := make([]byte, size)
	copy(pad[size-l:], data)
	return pad
}
