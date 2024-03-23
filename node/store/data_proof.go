package store

import (
	"encoding/binary"
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type DataProofStore interface {
	NewTransaction() (Transaction, error)
	GetAggregateProof(
		filter []byte,
		commitment []byte,
		frameNumber uint64,
	) (
		*protobufs.InclusionAggregateProof,
		error,
	)
	PutAggregateProof(
		txn Transaction,
		aggregateProof *protobufs.InclusionAggregateProof,
		commitment []byte,
	) error
}

var _ DataProofStore = (*PebbleDataProofStore)(nil)

type PebbleDataProofStore struct {
	db     KVDB
	logger *zap.Logger
}

func NewPebbleDataProofStore(
	db KVDB,
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
	return p.db.NewBatch(), nil
}

func internalGetAggregateProof(
	db KVDB,
	filter []byte,
	commitment []byte,
	frameNumber uint64,
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

	iter, err := db.NewIter(
		dataProofInclusionKey(filter, commitment, 0),
		dataProofInclusionKey(filter, commitment, limit+1),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get aggregate proof")
	}

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

		if string(url) == protobufs.IntrinsicExecutionOutputType {
			o := &protobufs.IntrinsicExecutionOutput{}
			copiedLeft := make([]byte, len(chunks[0]))
			copiedRight := make([]byte, len(chunks[1]))
			copy(copiedLeft, chunks[0])
			copy(copiedRight, chunks[1])

			o.Address = copiedLeft[:32]
			o.Output = copiedLeft[32:]
			o.Proof = copiedRight
			inclusionCommitment.Data, err = proto.Marshal(o)
			if err != nil {
				return nil, errors.Wrap(err, "get aggregate proof")
			}
		} else {
			copied := make([]byte, len(chunks[0]))
			copy(copied, chunks[0])
			inclusionCommitment.Data = copied
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

func internalListAggregateProofKeys(
	db KVDB,
	filter []byte,
	commitment []byte,
	frameNumber uint64,
) ([][]byte, [][]byte, [][]byte, error) {
	proofs := [][]byte{dataProofMetadataKey(filter, commitment)}
	commits := [][]byte{}
	data := [][]byte{}

	value, closer, err := db.Get(dataProofMetadataKey(filter, commitment))
	if err != nil {
		fmt.Println("proof lookup failed")

		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, nil, ErrNotFound
		}

		return nil, nil, nil, errors.Wrap(err, "list aggregate proof")
	}

	defer closer.Close()
	copied := make([]byte, len(value[8:]))
	limit := binary.BigEndian.Uint64(value[0:8])
	copy(copied, value[8:])

	iter, err := db.NewIter(
		dataProofInclusionKey(filter, commitment, 0),
		dataProofInclusionKey(filter, commitment, limit+1),
	)
	if err != nil {
		fmt.Println("inclusion lookup failed")

		return nil, nil, nil, errors.Wrap(err, "list aggregate proof")
	}

	i := uint32(0)
	commits = append(commits, dataProofInclusionKey(filter, commitment, 0))
	for iter.First(); iter.Valid(); iter.Next() {
		incCommit := iter.Value()

		urlLength := binary.BigEndian.Uint16(incCommit[:2])
		commitLength := binary.BigEndian.Uint16(incCommit[2:4])

		url := make([]byte, urlLength)
		copy(url, incCommit[4:urlLength+4])

		commit := make([]byte, commitLength)
		copy(commit, incCommit[urlLength+4:urlLength+4+commitLength])

		remainder := int(urlLength + 4 + commitLength)

		for j := 0; j < (len(incCommit)-remainder)/32; j++ {
			start := remainder + (j * 32)
			end := remainder + ((j + 1) * 32)

			data = append(data, dataProofSegmentKey(filter, incCommit[start:end]))
		}

		i++
	}

	if err = iter.Close(); err != nil {
		return nil, nil, nil, errors.Wrap(err, "list aggregate proof")
	}

	return proofs, commits, data, nil
}

func (p *PebbleDataProofStore) GetAggregateProof(
	filter []byte,
	commitment []byte,
	frameNumber uint64,
) (*protobufs.InclusionAggregateProof, error) {
	return internalGetAggregateProof(
		p.db,
		filter,
		commitment,
		frameNumber,
	)
}

func internalPutAggregateProof(
	db KVDB,
	txn Transaction,
	aggregateProof *protobufs.InclusionAggregateProof,
	commitment []byte,
) error {
	buf := binary.BigEndian.AppendUint64(
		nil,
		uint64(len(aggregateProof.InclusionCommitments)),
	)
	buf = append(buf, aggregateProof.Proof...)

	for i, inc := range aggregateProof.InclusionCommitments {
		var segments [][]byte
		if inc.TypeUrl == protobufs.IntrinsicExecutionOutputType {
			o := &protobufs.IntrinsicExecutionOutput{}
			if err := proto.Unmarshal(inc.Data, o); err != nil {
				return errors.Wrap(err, "get aggregate proof")
			}
			leftBits := append([]byte{}, o.Address...)
			leftBits = append(leftBits, o.Output...)
			rightBits := o.Proof
			segments = [][]byte{leftBits, rightBits}
		} else {
			segments = [][]byte{inc.Data}
		}

		urlLength := len(inc.TypeUrl)
		commitLength := len(inc.Commitment)
		encoded := binary.BigEndian.AppendUint16(nil, uint16(urlLength))
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(commitLength))

		encoded = append(encoded, []byte(inc.TypeUrl)...)
		encoded = append(encoded, inc.Commitment...)

		for _, segment := range segments {
			hash := sha3.Sum256(segment)
			if err := txn.Set(
				dataProofSegmentKey(aggregateProof.Filter, hash[:]),
				segment,
			); err != nil {
				return errors.Wrap(err, "put aggregate proof")
			}
			encoded = append(encoded, hash[:]...)
		}

		if err := txn.Set(
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
) error {
	return internalPutAggregateProof(
		p.db,
		txn,
		aggregateProof,
		commitment,
	)
}
