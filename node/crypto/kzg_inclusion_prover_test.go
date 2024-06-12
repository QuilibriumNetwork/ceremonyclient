package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func TestKZGVerifyFrame(t *testing.T) {
	kzg.TestInit("./kzg/ceremony.json")
	data := make([]byte, 1024)
	rand.Read(data)

	l, _ := zap.NewProduction()
	inclusionProver := crypto.NewKZGInclusionProver(l)

	commitment, err := inclusionProver.Commit(
		data,
		protobufs.IntrinsicExecutionOutputType,
	)
	assert.NoError(t, err)

	proof, err := inclusionProver.ProveAggregate(
		[]*crypto.InclusionCommitment{commitment},
	)
	assert.NoError(t, err)

	frame := &protobufs.ClockFrame{
		Filter:      []byte{0x00},
		FrameNumber: 1,
		Input:       bytes.Repeat([]byte{0x00}, 516),
		Output:      bytes.Repeat([]byte{0x00}, 516),
	}

	_, priv, _ := ed448.GenerateKey(rand.Reader)
	w := crypto.NewWesolowskiFrameProver(l)
	frame, err = w.ProveDataClockFrame(
		frame,
		[][]byte{proof.AggregateCommitment},
		[]*protobufs.InclusionAggregateProof{
			{
				Filter:      []byte{0x00},
				FrameNumber: 1,
				InclusionCommitments: []*protobufs.InclusionCommitment{
					{
						Filter:      []byte{0x00},
						FrameNumber: 1,
						TypeUrl:     proof.InclusionCommitments[0].TypeUrl,
						Commitment:  proof.InclusionCommitments[0].Commitment,
						Data:        data,
						Position:    0,
					},
				},
				Proof: proof.Proof,
			},
		},
		priv,
		time.Now().UnixMilli(),
		100,
	)

	err = inclusionProver.VerifyFrame(frame)
	assert.NoError(t, err)
}

func TestKZGInclusionProverRawFuncs(t *testing.T) {
	kzg.TestInit("./kzg/ceremony.json")
	data := make([]byte, 65536)
	rand.Read(data)

	l, _ := zap.NewProduction()
	inclusionProver := crypto.NewKZGInclusionProver(l)
	c, err := inclusionProver.CommitRaw(data, 1024)
	assert.NoError(t, err)

	p, err := inclusionProver.ProveRaw(data, 3, 1024)
	assert.NoError(t, err)

	v, err := inclusionProver.VerifyRaw(data[64*4:64*5], c, 3, p, 1024)
	assert.NoError(t, err)
	assert.True(t, v)
}
