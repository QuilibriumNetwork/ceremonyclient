package crypto_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func TestMasterProve(t *testing.T) {
	l, _ := zap.NewProduction()
	w := crypto.NewWesolowskiFrameProver(l)
	m, err := w.CreateMasterGenesisFrame([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, bytes.Repeat([]byte{0x00}, 516), 10000)
	assert.NoError(t, err)

	next, err := w.ProveMasterClockFrame(
		m,
		time.Now().UnixMilli(),
		10000,
		[]*protobufs.InclusionAggregateProof{},
	)
	assert.NoError(t, err)
	err = w.VerifyMasterClockFrame(next)
	assert.NoError(t, err)
}

func TestCalculateChallengeProofDifficulty(t *testing.T) {
	l, _ := zap.NewProduction()
	w := crypto.NewWesolowskiFrameProver(l)

	// At 0 increments, the difficulty should be 200,000
	difficulty0 := w.CalculateChallengeProofDifficulty(0)
	assert.Equal(t, 200000, difficulty0)

	// At 100,000 increments, the difficulty should be 175,000
	difficulty100k := w.CalculateChallengeProofDifficulty(100000)
	assert.Equal(t, 175000, difficulty100k)

	// At 700,000 increments, the difficulty should be 25,000
	difficulty700k := w.CalculateChallengeProofDifficulty(700000)
	assert.Equal(t, 25000, difficulty700k)

	// At 800,000 increments, the difficulty should stay at 25,000
	difficulty800k := w.CalculateChallengeProofDifficulty(800000)
	assert.Equal(t, 25000, difficulty800k)
}

func TestCalculateChallengeProofDifficulty(t *testing.T) {
	l, _ := zap.NewProduction()
	w := crypto.NewWesolowskiFrameProver(l)

	// At 0 increments, the difficulty should be 200,000
	difficulty0 := w.CalculateChallengeProofDifficulty(0)
	assert.Equal(t, 200000, difficulty0)

	// At 100,000 increments, the difficulty should be 175,000
	difficulty100k := w.CalculateChallengeProofDifficulty(100000)
	assert.Equal(t, 175000, difficulty100k)

	// At 700,000 increments, the difficulty should be 25,000
	difficulty700k := w.CalculateChallengeProofDifficulty(700000)
	assert.Equal(t, 25000, difficulty700k)

	// At 800,000 increments, the difficulty should stay at 25,000
	difficulty800k := w.CalculateChallengeProofDifficulty(800000)
	assert.Equal(t, 25000, difficulty800k)
}
