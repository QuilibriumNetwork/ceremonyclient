package store

import (
	"io"
)

type KVDB interface {
	Get(key []byte) ([]byte, io.Closer, error)
	Set(key, value []byte) error
	Delete(key []byte) error
	NewBatch() Transaction
	NewIter(lowerBound []byte, upperBound []byte) (Iterator, error)
	Compact(start, end []byte, parallelize bool) error
	CompactAll() error
	Close() error
	DeleteRange(start, end []byte) error
}
