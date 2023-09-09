package store

import "google.golang.org/protobuf/proto"

type Iterator[T proto.Message] interface {
	First() bool
	Next() bool
	Valid() bool
	Value() (T, error)
	Close() error
}
