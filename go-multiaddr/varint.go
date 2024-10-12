package multiaddr

import (
	"errors"
	"math"

	"github.com/multiformats/go-varint"
)

// CodeToVarint converts an integer to a varint-encoded []byte
func CodeToVarint(num int) ([]byte, error) {
	if num < 0 || num > math.MaxInt32 {
		return nil, errors.New("invalid code")
	}
	return varint.ToUvarint(uint64(num)), nil
}

func ReadVarintCode(b []byte) (int, int, error) {
	code, n, err := varint.FromUvarint(b)
	if err != nil {
		return 0, 0, err
	}
	if code > math.MaxInt32 {
		// we only allow 32bit codes.
		return 0, 0, varint.ErrOverflow
	}
	return int(code), n, err
}
