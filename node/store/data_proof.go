package store

import (
	"encoding/binary"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type DataProofStore interface {
	NewTransaction() (Transaction, error)
	GetAggregateProof(
		filter []byte,
		commitment []byte,
		frameNumber uint64,
		inclusionReassembler func(typeUrl string, data [][]byte) ([]byte, error),
	) (
		*protobufs.InclusionAggregateProof,
		error,
	)
	PutAggregateProof(
		txn Transaction,
		aggregateProof *protobufs.InclusionAggregateProof,
		commitment []byte,
		inclusionSplitter func(typeUrl string, data []byte) ([][]byte, error),
	) error
}

type PebbleDataProofStore struct {
	db     *pebble.DB
	logger *zap.Logger
}

func NewPebbleDataProofStore(
	db *pebble.DB,
	logger *zap.Logger,
) *PebbleDataProofStore {
	return &PebbleDataProofStore{
		db,
		logger,
	}
}

const (
	DATA_PROOF           = 0x04
	DATA_PROOF_METADATA  = 0x00
	DATA_PROOF_INCLUSION = 0x01
	DATA_PROOF_SEGMENT   = 0x02
)

func dataProofMetadataKey(filter []byte, commitment []byte) []byte {
	key := []byte{DATA_PROOF, DATA_PROOF_METADATA}
	key = append(key, commitment...)
	key = append(key, filter...)
	return key
}

func dataProofInclusionKey(
	filter []byte,
	commitment []byte,
	seqNo uint64,
) []byte {
	key := []byte{DATA_PROOF, DATA_PROOF_INCLUSION}
	key = append(key, commitment...)
	key = binary.BigEndian.AppendUint64(key, seqNo)
	key = append(key, filter...)
	return key
}

func dataProofSegmentKey(
	filter []byte,
	hash []byte,
) []byte {
	key := []byte{DATA_PROOF, DATA_PROOF_SEGMENT}
	key = append(key, hash...)
	key = append(key, filter...)
	return key
}

func (p *PebbleDataProofStore) NewTransaction() (Transaction, error) {
	return &PebbleTransaction{
		b: p.db.NewBatch(),
	}, nil
}

func internalGetAggregateProof(
	db *pebble.DB,
	filter []byte,
	commitment []byte,
	frameNumber uint64,
	inclusionReassembler func(typeUrl string, data [][]byte) ([]byte, error),
) (*protobufs.InclusionAggregateProof, error) {
	value, closer, err := db.Get(dataProofMetadataKey(filter, commitment))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get aggregate proof")
	}

	defer closer.Close()
	copied := make([]byte, len(value[8:]))
	limit := binary.BigEndian.Uint64(value[0:8])
	copy(copied, value[8:])

	aggregate := &protobufs.InclusionAggregateProof{
		Filter:               filter,
		FrameNumber:          frameNumber,
		InclusionCommitments: []*protobufs.InclusionCommitment{},
		Proof:                copied,
	}

	iter := db.NewIter(&pebble.IterOptions{
		LowerBound: dataProofInclusionKey(filter, commitment, 0),
		UpperBound: dataProofInclusionKey(filter, commitment, limit+1),
	})

	i := uint32(0)

	for iter.First(); iter.Valid(); iter.Next() {
		incCommit := iter.Value()

		urlLength := binary.BigEndian.Uint16(incCommit[:2])
		commitLength := binary.BigEndian.Uint16(incCommit[2:4])

		url := make([]byte, urlLength)
		copy(url, incCommit[4:urlLength+4])

		commit := make([]byte, commitLength)
		copy(commit, incCommit[urlLength+4:urlLength+4+commitLength])

		remainder := int(urlLength + 4 + commitLength)

		inclusionCommitment := &protobufs.InclusionCommitment{
			Filter:      filter,
			FrameNumber: frameNumber,
			Position:    i,
			TypeUrl:     string(url),
			Commitment:  commit,
		}

		chunks := [][]byte{}
		for j := 0; j < (len(incCommit)-remainder)/32; j++ {
			start := remainder + (j * 32)
			end := remainder + ((j + 1) * 32)
			segValue, dataCloser, err := db.Get(
				dataProofSegmentKey(filter, incCommit[start:end]),
			)
			if err != nil {
				if errors.Is(err, pebble.ErrNotFound) {
					// If we've lost this key it means we're in a corrupted state
					return nil, ErrInvalidData
				}

				return nil, errors.Wrap(err, "get aggregate proof")
			}

			segCopy := make([]byte, len(segValue))
			copy(segCopy, segValue)
			chunks = append(chunks, segCopy)

			if err = dataCloser.Close(); err != nil {
				return nil, errors.Wrap(err, "get aggregate proof")
			}
		}

		inclusionCommitment.Data, err = inclusionReassembler(string(url), chunks)
		if err != nil {
			return nil, errors.Wrap(err, "get aggregate proof")
		}

		aggregate.InclusionCommitments = append(
			aggregate.InclusionCommitments,
			inclusionCommitment,
		)
		i++
	}

	if err = iter.Close(); err != nil {
		return nil, errors.Wrap(err, "get aggregate proof")
	}

	return aggregate, nil
}

func (p *PebbleDataProofStore) GetAggregateProof(
	filter []byte,
	commitment []byte,
	frameNumber uint64,
	inclusionReassembler func(typeUrl string, data [][]byte) ([]byte, error),
) (*protobufs.InclusionAggregateProof, error) {
	return internalGetAggregateProof(
		p.db,
		filter,
		commitment,
		frameNumber,
		inclusionReassembler,
	)
}

func internalPutAggregateProof(
	db *pebble.DB,
	txn Transaction,
	aggregateProof *protobufs.InclusionAggregateProof,
	commitment []byte,
	inclusionSplitter func(typeUrl string, data []byte) ([][]byte, error),
) error {
	buf := binary.BigEndian.AppendUint64(
		nil,
		uint64(len(aggregateProof.InclusionCommitments)),
	)
	buf = append(buf, aggregateProof.Proof...)

	for i, inc := range aggregateProof.InclusionCommitments {
		segments, err := inclusionSplitter(inc.TypeUrl, inc.Data)
		if err != nil {
			return errors.Wrap(err, "get aggregate proof")
		}

		urlLength := len(inc.TypeUrl)
		commitLength := len(inc.Commitment)
		encoded := binary.BigEndian.AppendUint16(nil, uint16(urlLength))
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(commitLength))

		encoded = append(encoded, []byte(inc.TypeUrl)...)
		encoded = append(encoded, inc.Commitment...)

		for _, segment := range segments {
			hash := sha3.Sum256(segment)
			if err = txn.Set(
				dataProofSegmentKey(aggregateProof.Filter, hash[:]),
				segment,
			); err != nil {
				return errors.Wrap(err, "put aggregate proof")
			}
			encoded = append(encoded, hash[:]...)
		}

		if err = txn.Set(
			dataProofInclusionKey(aggregateProof.Filter, commitment, uint64(i)),
			encoded,
		); err != nil {
			return errors.Wrap(err, "put aggregate proof")
		}
	}

	if err := txn.Set(
		dataProofMetadataKey(aggregateProof.Filter, commitment),
		buf,
	); err != nil {
		return errors.Wrap(err, "put aggregate proof")
	}

	return nil
}

func (p *PebbleDataProofStore) PutAggregateProof(
	txn Transaction,
	aggregateProof *protobufs.InclusionAggregateProof,
	commitment []byte,
	inclusionSplitter func(typeUrl string, data []byte) ([][]byte, error),
) error {
	return internalPutAggregateProof(
		p.db,
		txn,
		aggregateProof,
		commitment,
		inclusionSplitter,
	)
}
