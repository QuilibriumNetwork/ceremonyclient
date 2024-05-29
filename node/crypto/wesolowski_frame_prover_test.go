package crypto_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
)

func TestMasterProve(t *testing.T) {
	l, _ := zap.NewProduction()
	w := crypto.NewWesolowskiFrameProver(l)
	m, err := w.CreateMasterGenesisFrame([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}, bytes.Repeat([]byte{0x00}, 516), 10000)
	assert.NoError(t, err)

	next, err := w.ProveMasterClockFrame(m, time.Now().UnixMilli(), 10000)
	assert.NoError(t, err)
	err = w.VerifyMasterClockFrame(next)
	assert.NoError(t, err)
}

func TestChallengeProof(t *testing.T) {
	l, _ := zap.NewProduction()
	w := crypto.NewWesolowskiFrameProver(l)
	now := time.Now().UnixMilli()
	proofs, nextSkew, err := w.CalculateChallengeProof([]byte{0x01, 0x02, 0x03}, 0, 120000, now)
	assert.NoError(t, err)
	assert.True(t, w.VerifyChallengeProof([]byte{0x01, 0x02, 0x03}, now, 100000, [][]byte{proofs}))
	now = time.Now().UnixMilli()
	proofs, _, err = w.CalculateChallengeProof([]byte{0x01, 0x02, 0x03}, 0, nextSkew*12/10, now)
	assert.NoError(t, err)
	assert.True(t, w.VerifyChallengeProof([]byte{0x01, 0x02, 0x03}, now, nextSkew, [][]byte{proofs}))
}
