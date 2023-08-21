package tries_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func TestSerializers(t *testing.T) {
	tree := &tries.RollingFrecencyCritbitTrie{}
	for i := 0; i < 10000; i++ {
		seed := make([]byte, 57)
		rand.Read(seed)

		priv := ed448.NewKeyFromSeed(seed)
		pubkey := (priv.Public()).(ed448.PublicKey)
		addr, err := poseidon.HashBytes(pubkey)
		assert.NoError(t, err)

		v := uint64(i)
		a := addr.Bytes()
		b := make([]byte, 32)
		copy(b[32-len(a):], addr.Bytes())

		tree.Add(b, v)
	}

	newTree := &tries.RollingFrecencyCritbitTrie{}
	buf, err := tree.Serialize()
	assert.NoError(t, err)
	err = newTree.Deserialize(buf)
	assert.NoError(t, err)

	for i := 0; i < 256; i++ {
		seed := make([]byte, 57)
		rand.Read(seed)

		priv := ed448.NewKeyFromSeed(seed)
		pubkey := (priv.Public()).(ed448.PublicKey)
		disc, err := poseidon.HashBytes(pubkey)
		assert.NoError(t, err)

		newTreeNeighbors := newTree.FindNearestAndApproximateNeighbors(disc.Bytes())
		for i, n := range tree.FindNearestAndApproximateNeighbors(disc.Bytes()) {
			assert.Equal(t, n.Bits(), newTreeNeighbors[i].Bits())
		}
	}
}

func TestCritbit(t *testing.T) {
	tree := &tries.RollingFrecencyCritbitTrie{}

	for i := 0; i < 100000; i++ {
		seed := make([]byte, 57)
		rand.Read(seed)

		priv := ed448.NewKeyFromSeed(seed)
		pubkey := (priv.Public()).(ed448.PublicKey)
		addr, err := poseidon.HashBytes(pubkey)
		assert.NoError(t, err)

		v := uint64(i)
		a := addr.Bytes()
		b := make([]byte, 32)
		copy(b[32-len(a):], addr.Bytes())

		tree.Add(b, v)
	}

	for i := 0; i < 256; i++ {
		seed := make([]byte, 57)
		rand.Read(seed)

		priv := ed448.NewKeyFromSeed(seed)
		pubkey := (priv.Public()).(ed448.PublicKey)
		disc, err := poseidon.HashBytes(pubkey)
		assert.NoError(t, err)

		for _, n := range tree.FindNearestAndApproximateNeighbors(disc.Bytes()) {
			diff := new(big.Int)
			diff.SetBytes(n.Bits())
			diff.Sub(diff, disc)
			diff.Abs(diff)
		}
	}
}
