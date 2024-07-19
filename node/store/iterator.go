package store

import "google.golang.org/protobuf/proto"

type Iterator interface {
	Key() []byte
	First() bool
	Next() bool
	Prev() bool
	Valid() bool
	Value() []byte
	Close() error
	SeekLT([]byte) bool
	Last() bool
}

type TypedIterator[T proto.Message] interface {
	First() bool
	Next() bool
	Valid() bool
	Value() (T, error)
	Close() error
}
