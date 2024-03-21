package store

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/cockroachdb/pebble"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type ClockStore interface {
	NewTransaction() (Transaction, error)
	GetLatestMasterClockFrame(filter []byte) (*protobufs.ClockFrame, error)
	GetEarliestMasterClockFrame(filter []byte) (*protobufs.ClockFrame, error)
	GetMasterClockFrame(
		filter []byte,
		frameNumber uint64,
	) (*protobufs.ClockFrame, error)
	RangeMasterClockFrames(
		filter []byte,
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (*PebbleMasterClockIterator, error)
	PutMasterClockFrame(frame *protobufs.ClockFrame, txn Transaction) error
	GetLatestDataClockFrame(
		filter []byte,
		proverTrie *tries.RollingFrecencyCritbitTrie,
	) (*protobufs.ClockFrame, error)
	GetEarliestDataClockFrame(filter []byte) (*protobufs.ClockFrame, error)
	GetDataClockFrame(
		filter []byte,
		frameNumber uint64,
		truncate bool,
	) (*protobufs.ClockFrame, *tries.RollingFrecencyCritbitTrie, error)
	RangeDataClockFrames(
		filter []byte,
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (*PebbleClockIterator, error)
	CommitDataClockFrame(
		filter []byte,
		frameNumber uint64,
		selector []byte,
		proverTrie *tries.RollingFrecencyCritbitTrie,
		txn Transaction,
		backfill bool,
	) error
	StageDataClockFrame(
		selector []byte,
		frame *protobufs.ClockFrame,
		txn Transaction,
	) error
	GetStagedDataClockFrame(
		filter []byte,
		frameNumber uint64,
		parentSelector []byte,
		truncate bool,
	) (*protobufs.ClockFrame, error)
	GetCompressedDataClockFrames(
		filter []byte,
		fromFrameNumber uint64,
		toFrameNumber uint64,
	) (*protobufs.CeremonyCompressedSync, error)
	SetLatestDataClockFrameNumber(
		filter []byte,
		frameNumber uint64,
	) error
	ResetMasterClockFrames(filter []byte) error
	ResetDataClockFrames(filter []byte) error
	Compact(
		masterFilter []byte,
		dataFilter []byte,
	) error
	GetTotalDistance(
		filter []byte,
		frameNumber uint64,
		selector []byte,
	) (*big.Int, error)
	SetTotalDistance(
		filter []byte,
		frameNumber uint64,
		selector []byte,
		totalDistance *big.Int,
	) error
}

type PebbleClockStore struct {
	db     KVDB
	logger *zap.Logger
}

var _ ClockStore = (*PebbleClockStore)(nil)

type PebbleMasterClockIterator struct {
	i Iterator
}

type PebbleClockIterator struct {
	i  Iterator
	db *PebbleClockStore
}

var _ TypedIterator[*protobufs.ClockFrame] = (*PebbleMasterClockIterator)(nil)
var _ TypedIterator[*protobufs.ClockFrame] = (*PebbleClockIterator)(nil)

func (p *PebbleMasterClockIterator) First() bool {
	return p.i.First()
}

func (p *PebbleMasterClockIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleMasterClockIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleMasterClockIterator) Value() (*protobufs.ClockFrame, error) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	key := p.i.Key()
	value := p.i.Value()
	frame := &protobufs.ClockFrame{}

	frameNumber, filter, err := extractFrameNumberAndFilterFromMasterFrameKey(key)
	if err != nil {
		return nil, errors.Wrap(err, "get master clock frame iterator value")
	}

	frame.FrameNumber = frameNumber
	frame.Filter = make([]byte, len(filter))
	copy(frame.Filter, filter)

	if len(value) < 521 {
		return nil, errors.Wrap(
			ErrInvalidData,
			"get master clock frame iterator value",
		)
	}

	copied := make([]byte, len(value))
	copy(copied, value)

	frame.Difficulty = binary.BigEndian.Uint32(copied[:4])
	frame.Input = copied[4 : len(copied)-516]
	frame.Output = copied[len(copied)-516:]

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "get master clock frame iterator value")
	}

	frame.ParentSelector = parent.FillBytes(make([]byte, 32))

	return frame, nil
}

func (p *PebbleMasterClockIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing master clock iterator")
}

func (p *PebbleClockIterator) First() bool {
	return p.i.First()
}

func (p *PebbleClockIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleClockIterator) Prev() bool {
	return p.i.Prev()
}

func (p *PebbleClockIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleClockIterator) TruncatedValue() (
	*protobufs.ClockFrame,
	error,
) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.ClockFrame{}
	if len(value) == (len(p.i.Key()) + 32) {
		frameValue, frameCloser, err := p.db.db.Get(value)
		if err != nil {
			return nil, errors.Wrap(err, "get truncated clock frame iterator value")
		}
		if err := proto.Unmarshal(frameValue, frame); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get truncated clock frame iterator value",
			)
		}
		frameCloser.Close()
	} else {
		if err := proto.Unmarshal(value, frame); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get truncated clock frame iterator value",
			)
		}
	}

	return frame, nil
}

func (p *PebbleClockIterator) Value() (*protobufs.ClockFrame, error) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.ClockFrame{}
	genesisFramePreIndex := false

	// We do a bit of a cheap trick here while things are still stuck in the old
	// ways: we use the size of the parent index key to determine if it's the new
	// format, or the old raw frame
	if len(value) == (len(p.i.Key()) + 32) {
		frameValue, frameCloser, err := p.db.db.Get(value)
		if err != nil {
			return nil, errors.Wrap(err, "get clock frame iterator value")
		}
		if err := proto.Unmarshal(frameValue, frame); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get clock frame iterator value",
			)
		}
		defer frameCloser.Close()
	} else {
		if err := proto.Unmarshal(value, frame); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get clock frame iterator value",
			)
		}
		genesisFramePreIndex = frame.FrameNumber == 0
	}

	if err := p.db.fillAggregateProofs(frame, genesisFramePreIndex); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get clock frame iterator value",
		)
	}

	return frame, nil
}

func (p *PebbleClockIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing clock frame iterator")
}

func NewPebbleClockStore(db KVDB, logger *zap.Logger) *PebbleClockStore {
	return &PebbleClockStore{
		db,
		logger,
	}
}

const CLOCK_FRAME = 0x00
const CLOCK_MASTER_FRAME_DATA = 0x00
const CLOCK_DATA_FRAME_DATA = 0x01
const CLOCK_DATA_FRAME_CANDIDATE_DATA = 0x02
const CLOCK_DATA_FRAME_FRECENCY_DATA = 0x03
const CLOCK_DATA_FRAME_DISTANCE_DATA = 0x04
const CLOCK_MASTER_FRAME_INDEX_EARLIEST = 0x10 | CLOCK_MASTER_FRAME_DATA
const CLOCK_MASTER_FRAME_INDEX_LATEST = 0x20 | CLOCK_MASTER_FRAME_DATA
const CLOCK_MASTER_FRAME_INDEX_PARENT = 0x30 | CLOCK_MASTER_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_EARLIEST = 0x10 | CLOCK_DATA_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_LATEST = 0x20 | CLOCK_DATA_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_PARENT = 0x30 | CLOCK_DATA_FRAME_DATA
const CLOCK_DATA_FRAME_CANDIDATE_INDEX_LATEST = 0x20 |
	CLOCK_DATA_FRAME_CANDIDATE_DATA

//
// DB Keys
//
// Keys are structured as:
// <core type><sub type | index>[<non-index increment>]<segment>
// Increment necessarily must be full width – elsewise the frame number would
// easily produce conflicts if filters are stepped by byte:
// 0x01 || 0xffff == 0x01ff || 0xff
//
// Master frames are serialized as output data only, Data frames are raw
// protobufs for fast disk-to-network output.

func clockFrameKey(filter []byte, frameNumber uint64, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	return key
}

func clockMasterFrameKey(filter []byte, frameNumber uint64) []byte {
	return clockFrameKey(filter, frameNumber, CLOCK_MASTER_FRAME_DATA)
}

func extractFrameNumberAndFilterFromMasterFrameKey(
	key []byte,
) (uint64, []byte, error) {
	if len(key) < 11 {
		return 0, nil, errors.Wrap(
			ErrInvalidData,
			"extract frame number and filter from master frame key",
		)
	}

	copied := make([]byte, len(key))
	copy(copied, key)
	return binary.BigEndian.Uint64(copied[2:10]), copied[10:], nil
}

func clockDataFrameKey(
	filter []byte,
	frameNumber uint64,
) []byte {
	return clockFrameKey(filter, frameNumber, CLOCK_DATA_FRAME_DATA)
}

func clockLatestIndex(filter []byte, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = append(key, filter...)
	return key
}

func clockMasterLatestIndex(filter []byte) []byte {
	return clockLatestIndex(filter, CLOCK_MASTER_FRAME_INDEX_LATEST)
}

func clockDataLatestIndex(filter []byte) []byte {
	return clockLatestIndex(filter, CLOCK_DATA_FRAME_INDEX_LATEST)
}

func clockDataCandidateLatestIndex(filter []byte) []byte {
	return clockLatestIndex(filter, CLOCK_DATA_FRAME_CANDIDATE_INDEX_LATEST)
}

func clockEarliestIndex(filter []byte, frameType byte) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = append(key, filter...)
	return key
}

func clockMasterEarliestIndex(filter []byte) []byte {
	return clockEarliestIndex(filter, CLOCK_MASTER_FRAME_INDEX_EARLIEST)
}

func clockDataEarliestIndex(filter []byte) []byte {
	return clockEarliestIndex(filter, CLOCK_DATA_FRAME_INDEX_EARLIEST)
}

// Produces an index key of size: len(filter) + 42
func clockParentIndexKey(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	frameType byte,
) []byte {
	key := []byte{CLOCK_FRAME, frameType}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	key = append(key, rightAlign(selector, 32)...)
	return key
}

func clockDataParentIndexKey(
	filter []byte,
	frameNumber uint64,
	selector []byte,
) []byte {
	return clockParentIndexKey(
		filter,
		frameNumber,
		rightAlign(selector, 32),
		CLOCK_DATA_FRAME_INDEX_PARENT,
	)
}

func clockDataCandidateFrameKey(
	filter []byte,
	frameNumber uint64,
	parent []byte,
	distance []byte,
) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_DATA_FRAME_CANDIDATE_DATA}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	key = append(key, rightAlign(parent, 32)...)
	key = append(key, rightAlign(distance, 32)...)
	return key
}

func clockProverTrieKey(filter []byte, frameNumber uint64) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_DATA_FRAME_FRECENCY_DATA}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	return key
}

func clockDataTotalDistanceKey(
	filter []byte,
	frameNumber uint64,
	selector []byte,
) []byte {
	key := []byte{CLOCK_FRAME, CLOCK_DATA_FRAME_DISTANCE_DATA}
	key = binary.BigEndian.AppendUint64(key, frameNumber)
	key = append(key, filter...)
	key = append(key, rightAlign(selector, 32)...)
	return key
}

func (p *PebbleClockStore) NewTransaction() (Transaction, error) {
	return p.db.NewBatch(), nil
}

// GetEarliestMasterClockFrame implements ClockStore.
func (p *PebbleClockStore) GetEarliestMasterClockFrame(
	filter []byte,
) (*protobufs.ClockFrame, error) {
	idxValue, closer, err := p.db.Get(clockMasterEarliestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get earliest master clock frame")
	}

	defer closer.Close()
	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, err := p.GetMasterClockFrame(filter, frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "get earliest master clock frame")
	}

	return frame, nil
}

// GetLatestMasterClockFrame implements ClockStore.
func (p *PebbleClockStore) GetLatestMasterClockFrame(
	filter []byte,
) (*protobufs.ClockFrame, error) {
	idxValue, closer, err := p.db.Get(clockMasterLatestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get latest master clock frame")
	}

	defer closer.Close()
	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, err := p.GetMasterClockFrame(filter, frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "get latest master clock frame")
	}

	return frame, nil
}

// GetMasterClockFrame implements ClockStore.
func (p *PebbleClockStore) GetMasterClockFrame(
	filter []byte,
	frameNumber uint64,
) (*protobufs.ClockFrame, error) {
	value, closer, err := p.db.Get(clockMasterFrameKey(filter, frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get master clock frame")
	}

	copied := make([]byte, len(value))
	copy(copied[:], value[:])

	defer closer.Close()
	frame := &protobufs.ClockFrame{}
	frame.FrameNumber = frameNumber
	frame.Filter = filter
	frame.Difficulty = binary.BigEndian.Uint32(copied[:4])
	frame.Input = copied[4 : len(copied)-516]
	frame.Output = copied[len(copied)-516:]

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "get master clock frame")
	}

	frame.ParentSelector = parent.FillBytes(make([]byte, 32))

	return frame, nil
}

// RangeMasterClockFrames implements ClockStore.
func (p *PebbleClockStore) RangeMasterClockFrames(
	filter []byte,
	startFrameNumber uint64,
	endFrameNumber uint64,
) (*PebbleMasterClockIterator, error) {
	if startFrameNumber > endFrameNumber {
		temp := endFrameNumber
		endFrameNumber = startFrameNumber
		startFrameNumber = temp
	}

	iter, err := p.db.NewIter(
		clockMasterFrameKey(filter, startFrameNumber),
		clockMasterFrameKey(filter, endFrameNumber),
	)
	if err != nil {
		return nil, errors.Wrap(err, "range master clock frames")
	}

	return &PebbleMasterClockIterator{i: iter}, nil
}

// PutMasterClockFrame implements ClockStore.
func (p *PebbleClockStore) PutMasterClockFrame(
	frame *protobufs.ClockFrame,
	txn Transaction,
) error {
	data := binary.BigEndian.AppendUint32([]byte{}, frame.Difficulty)
	data = append(data, frame.Input...)
	data = append(data, frame.Output...)

	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, frame.FrameNumber)

	if err := txn.Set(
		clockMasterFrameKey(frame.Filter, frame.FrameNumber),
		data,
	); err != nil {
		return errors.Wrap(err, "put master clock frame")
	}

	_, closer, err := p.db.Get(clockMasterEarliestIndex(frame.Filter))
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "put master clock frame")
		}

		if err = txn.Set(
			clockMasterEarliestIndex(frame.Filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "put master clock frame")
		}
	}

	if err == nil && closer != nil {
		closer.Close()
	}

	if err = txn.Set(
		clockMasterLatestIndex(frame.Filter),
		frameNumberBytes,
	); err != nil {
		return errors.Wrap(err, "put master clock frame")
	}

	return nil
}

// GetDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetDataClockFrame(
	filter []byte,
	frameNumber uint64,
	truncate bool,
) (*protobufs.ClockFrame, *tries.RollingFrecencyCritbitTrie, error) {
	value, closer, err := p.db.Get(clockDataFrameKey(filter, frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, ErrNotFound
		}

		return nil, nil, errors.Wrap(err, "get data clock frame")
	}

	frame := &protobufs.ClockFrame{}
	genesisFramePreIndex := false

	// We do a bit of a cheap trick here while things are still stuck in the old
	// ways: we use the size of the parent index key to determine if it's the new
	// format, or the old raw frame
	if len(value) == (len(filter) + 42) {
		frameValue, frameCloser, err := p.db.Get(value)
		if err != nil {
			return nil, nil, errors.Wrap(err, "get data clock frame")
		}
		if err := proto.Unmarshal(frameValue, frame); err != nil {
			return nil, nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get data clock frame",
			)
		}
		closer.Close()
		defer frameCloser.Close()
	} else {
		genesisFramePreIndex = frameNumber == 0
		if err := proto.Unmarshal(value, frame); err != nil {
			return nil, nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get data clock frame",
			)
		}
		defer closer.Close()
	}

	if !truncate {
		if err = p.fillAggregateProofs(frame, genesisFramePreIndex); err != nil {
			return nil, nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get data clock frame",
			)
		}

		proverTrie := &tries.RollingFrecencyCritbitTrie{}

		trieData, closer, err := p.db.Get(clockProverTrieKey(filter, frameNumber))
		if err != nil {
			return nil, nil, errors.Wrap(err, "get latest data clock frame")
		}

		defer closer.Close()

		if err := proverTrie.Deserialize(trieData); err != nil {
			return nil, nil, errors.Wrap(err, "get latest data clock frame")
		}

		return frame, proverTrie, nil
	}

	return frame, nil, nil
}

func (p *PebbleClockStore) fillAggregateProofs(
	frame *protobufs.ClockFrame,
	genesisFramePreIndex bool,
) error {
	if frame.FrameNumber == 0 && genesisFramePreIndex {
		return nil
	}

	for i := 0; i < len(frame.Input[516:])/74; i++ {
		commit := frame.Input[516+(i*74) : 516+((i+1)*74)]
		ap, err := internalGetAggregateProof(
			p.db,
			frame.Filter,
			commit,
			frame.FrameNumber,
		)
		if err != nil {
			return err
		}

		frame.AggregateProofs = append(frame.AggregateProofs, ap)
	}

	return nil
}

func (p *PebbleClockStore) saveAggregateProofs(
	txn Transaction,
	frame *protobufs.ClockFrame,
) error {
	shouldClose := false
	if txn == nil {
		var err error
		txn, err = p.NewTransaction()
		if err != nil {
			return err
		}

		shouldClose = true
	}

	for i := 0; i < len(frame.Input[516:])/74; i++ {
		commit := frame.Input[516+(i*74) : 516+((i+1)*74)]
		err := internalPutAggregateProof(
			p.db,
			txn,
			frame.AggregateProofs[i],
			commit,
		)
		if err != nil {
			if err = txn.Abort(); err != nil {
				return err
			}
		}
	}

	if shouldClose {
		txn.Commit()
	}

	return nil
}

// GetEarliestDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetEarliestDataClockFrame(
	filter []byte,
) (*protobufs.ClockFrame, error) {
	idxValue, closer, err := p.db.Get(clockDataEarliestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get earliest data clock frame")
	}

	defer closer.Close()
	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, _, err := p.GetDataClockFrame(filter, frameNumber, false)
	if err != nil {
		return nil, errors.Wrap(err, "get earliest data clock frame")
	}

	return frame, nil
}

// GetLatestDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetLatestDataClockFrame(
	filter []byte,
	proverTrie *tries.RollingFrecencyCritbitTrie,
) (*protobufs.ClockFrame, error) {
	idxValue, closer, err := p.db.Get(clockDataLatestIndex(filter))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get latest data clock frame")
	}

	frameNumber := binary.BigEndian.Uint64(idxValue)
	frame, _, err := p.GetDataClockFrame(filter, frameNumber, false)
	if err != nil {
		return nil, errors.Wrap(err, "get latest data clock frame")
	}

	closer.Close()
	if proverTrie != nil {
		trieData, closer, err := p.db.Get(clockProverTrieKey(filter, frameNumber))
		if err != nil {
			return nil, errors.Wrap(err, "get latest data clock frame")
		}

		defer closer.Close()

		if err := proverTrie.Deserialize(trieData); err != nil {
			return nil, errors.Wrap(err, "get latest data clock frame")
		}
	}

	return frame, nil
}

// GetStagedDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetStagedDataClockFrame(
	filter []byte,
	frameNumber uint64,
	parentSelector []byte,
	truncate bool,
) (*protobufs.ClockFrame, error) {
	data, closer, err := p.db.Get(
		clockDataParentIndexKey(filter, frameNumber, parentSelector),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, errors.Wrap(ErrNotFound, "get parent data clock frame")
		}
		return nil, errors.Wrap(err, "get parent data clock frame")
	}

	parent := &protobufs.ClockFrame{}
	if err := proto.Unmarshal(data, parent); err != nil {
		return nil, errors.Wrap(err, "get parent data clock frame")
	}

	if !truncate {
		if err := p.fillAggregateProofs(parent, false); err != nil {
			return nil, errors.Wrap(
				errors.Wrap(err, ErrInvalidData.Error()),
				"get clock frame iterator value",
			)
		}
	}

	if closer != nil {
		closer.Close()
	}

	return parent, nil
}

// StageDataClockFrame implements ClockStore.
func (p *PebbleClockStore) StageDataClockFrame(
	selector []byte,
	frame *protobufs.ClockFrame,
	txn Transaction,
) error {
	if err := p.saveAggregateProofs(txn, frame); err != nil {
		return errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"stage data clock frame",
		)
	}

	temp := append(
		[]*protobufs.InclusionAggregateProof{},
		frame.AggregateProofs...,
	)
	frame.AggregateProofs = []*protobufs.InclusionAggregateProof{}

	data, err := proto.Marshal(frame)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"stage data clock frame",
		)
	}

	frame.AggregateProofs = temp

	if err = txn.Set(
		clockDataParentIndexKey(
			frame.Filter,
			frame.FrameNumber,
			selector,
		),
		data,
	); err != nil {
		return errors.Wrap(err, "stage data clock frame")
	}

	return nil
}

// CommitDataClockFrame implements ClockStore.
func (p *PebbleClockStore) CommitDataClockFrame(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	proverTrie *tries.RollingFrecencyCritbitTrie,
	txn Transaction,
	backfill bool,
) error {
	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, frameNumber)

	if err := txn.Set(
		clockDataFrameKey(filter, frameNumber),
		clockDataParentIndexKey(filter, frameNumber, selector),
	); err != nil {
		return errors.Wrap(err, "commit data clock frame")
	}

	proverData, err := proverTrie.Serialize()
	if err != nil {
		return errors.Wrap(err, "commit data clock frame")
	}

	if err = txn.Set(
		clockProverTrieKey(filter, frameNumber),
		proverData,
	); err != nil {
		return errors.Wrap(err, "commit data clock frame")
	}

	_, closer, err := p.db.Get(clockDataEarliestIndex(filter))
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "commit data clock frame")
		}

		if err = txn.Set(
			clockDataEarliestIndex(filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "commit data clock frame")
		}
	}

	if err == nil && closer != nil {
		closer.Close()
	}

	if !backfill {
		if err = txn.Set(
			clockDataLatestIndex(filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "commit data clock frame")
		}
	}

	return nil
}

// RangeDataClockFrames implements ClockStore.
func (p *PebbleClockStore) RangeDataClockFrames(
	filter []byte,
	startFrameNumber uint64,
	endFrameNumber uint64,
) (*PebbleClockIterator, error) {
	if startFrameNumber > endFrameNumber {
		temp := endFrameNumber
		endFrameNumber = startFrameNumber
		startFrameNumber = temp
	}

	iter, err := p.db.NewIter(
		clockDataFrameKey(filter, startFrameNumber),
		clockDataFrameKey(filter, endFrameNumber),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get data clock frames")
	}

	return &PebbleClockIterator{i: iter, db: p}, nil
}

func (p *PebbleClockStore) GetCompressedDataClockFrames(
	filter []byte,
	fromFrameNumber uint64,
	toFrameNumber uint64,
) (*protobufs.CeremonyCompressedSync, error) {
	from := clockDataFrameKey(filter, fromFrameNumber)
	to := clockDataFrameKey(filter, toFrameNumber+1)

	iter, err := p.db.NewIter(from, to)
	if err != nil {
		return nil, errors.Wrap(err, "get compressed data clock frames")
	}

	syncMessage := &protobufs.CeremonyCompressedSync{}
	proofs := map[string]*protobufs.InclusionProofsMap{}
	commits := map[string]*protobufs.InclusionCommitmentsMap{}
	segments := map[string]*protobufs.InclusionSegmentsMap{}

	for iter.First(); iter.Valid(); iter.Next() {
		value := iter.Value()
		frame := &protobufs.ClockFrame{}
		genesisFramePreIndex := false

		// We do a bit of a cheap trick here while things are still stuck in the old
		// ways: we use the size of the parent index key to determine if it's the
		// new format, or the old raw frame
		if len(value) == (len(filter) + 42) {
			frameValue, frameCloser, err := p.db.Get(value)
			if err != nil {
				return nil, errors.Wrap(err, "get compressed data clock frames")
			}
			if err := proto.Unmarshal(frameValue, frame); err != nil {
				return nil, errors.Wrap(
					errors.Wrap(err, ErrInvalidData.Error()),
					"get compressed data clock frames",
				)
			}
			frameCloser.Close()
		} else {
			if err := proto.Unmarshal(value, frame); err != nil {
				return nil, errors.Wrap(
					errors.Wrap(err, ErrInvalidData.Error()),
					"get compressed data clock frames",
				)
			}
			genesisFramePreIndex = frame.FrameNumber == 0
		}

		if err := proto.Unmarshal(value, frame); err != nil {
			return nil, errors.Wrap(err, "get compressed data clock frames")
		}

		syncMessage.TruncatedClockFrames = append(
			syncMessage.TruncatedClockFrames,
			frame,
		)
		if frame.FrameNumber == 0 && genesisFramePreIndex {
			continue
		}
		for i := 0; i < len(frame.Input[516:])/74; i++ {
			aggregateCommit := frame.Input[516+(i*74) : 516+((i+1)*74)]

			if _, ok := proofs[string(aggregateCommit)]; !ok {
				proofs[string(aggregateCommit)] = &protobufs.InclusionProofsMap{
					FrameCommit: aggregateCommit,
				}
			}
		}
	}

	if err := iter.Close(); err != nil {
		return nil, errors.Wrap(err, "get compressed data clock frames")
	}

	for k, v := range proofs {
		k := k
		v := v
		value, closer, err := p.db.Get(dataProofMetadataKey(filter, []byte(k)))
		if err != nil {
			if errors.Is(err, pebble.ErrNotFound) {
				return nil, ErrNotFound
			}

			return nil, errors.Wrap(err, "get compressed data clock frames")
		}

		copied := make([]byte, len(value[8:]))
		limit := binary.BigEndian.Uint64(value[0:8])
		copy(copied, value[8:])
		v.Proof = copied
		if err = closer.Close(); err != nil {
			return nil, errors.Wrap(err, "get compressed data clock frames")
		}

		iter, err := p.db.NewIter(
			dataProofInclusionKey(filter, []byte(k), 0),
			dataProofInclusionKey(filter, []byte(k), limit+1),
		)
		if err != nil {
			return nil, errors.Wrap(err, "get compressed data clock frames")
		}

		for iter.First(); iter.Valid(); iter.Next() {
			incCommit := iter.Value()

			urlLength := binary.BigEndian.Uint16(incCommit[:2])
			commitLength := binary.BigEndian.Uint16(incCommit[2:4])

			url := make([]byte, urlLength)
			copy(url, incCommit[4:urlLength+4])

			commit := make([]byte, commitLength)
			copy(commit, incCommit[urlLength+4:urlLength+4+commitLength])

			remainder := int(urlLength + 4 + commitLength)
			if _, ok := commits[string(commit)]; !ok {
				commits[string(commit)] = &protobufs.InclusionCommitmentsMap{
					Commitment: commit,
					TypeUrl:    string(url),
				}

				for j := 0; j < (len(incCommit)-remainder)/32; j++ {
					start := remainder + (j * 32)
					end := remainder + ((j + 1) * 32)
					hash := make([]byte, len(incCommit[start:end]))
					copy(hash, incCommit[start:end])

					commits[string(commit)].SegmentHashes = append(
						commits[string(commit)].SegmentHashes,
						hash,
					)

					if _, ok := segments[string(hash)]; !ok {
						segValue, dataCloser, err := p.db.Get(
							dataProofSegmentKey(filter, incCommit[start:end]),
						)

						if err != nil {
							if errors.Is(err, pebble.ErrNotFound) {
								// If we've lost this key it means we're in a corrupted state
								return nil, ErrInvalidData
							}

							return nil, errors.Wrap(err, "get compressed data clock frames")
						}

						segCopy := make([]byte, len(segValue))
						copy(segCopy, segValue)

						segments[string(hash)] = &protobufs.InclusionSegmentsMap{
							Hash: hash,
							Data: segCopy,
						}
						syncMessage.Segments = append(
							syncMessage.Segments,
							segments[string(hash)],
						)

						if err = dataCloser.Close(); err != nil {
							return nil, errors.Wrap(err, "get compressed data clock frames")
						}
					}
				}
			}

			v.Commitments = append(v.Commitments, commits[string(commit)])
		}

		syncMessage.Proofs = append(
			syncMessage.Proofs,
			v,
		)

		if len(syncMessage.TruncatedClockFrames) > 0 {
			frames := syncMessage.TruncatedClockFrames
			syncMessage.FromFrameNumber = frames[0].FrameNumber
			syncMessage.ToFrameNumber = frames[len(frames)-1].FrameNumber
		}

		if err = iter.Close(); err != nil {
			return nil, errors.Wrap(err, "get aggregate proof")
		}
	}

	return syncMessage, nil
}

func (p *PebbleClockStore) SetLatestDataClockFrameNumber(
	filter []byte,
	frameNumber uint64,
) error {
	err := p.db.Set(
		clockDataLatestIndex(filter),
		binary.BigEndian.AppendUint64(nil, frameNumber),
	)

	return errors.Wrap(err, "set latest data clock frame number")
}

func (p *PebbleClockStore) DeleteDataClockFrameRange(
	filter []byte,
	fromFrameNumber uint64,
	toFrameNumber uint64,
) error {
	err := p.db.DeleteRange(
		clockDataFrameKey(
			filter,
			fromFrameNumber,
		),
		clockDataFrameKey(
			filter,
			toFrameNumber,
		),
	)
	return errors.Wrap(err, "delete data clock frame range")
}

func (p *PebbleClockStore) ResetMasterClockFrames(filter []byte) error {
	if err := p.db.DeleteRange(
		clockMasterFrameKey(filter, 0),
		clockMasterFrameKey(filter, 200000),
	); err != nil {
		return errors.Wrap(err, "reset master clock frames")
	}

	if err := p.db.Delete(clockMasterEarliestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset master clock frames")
	}

	if err := p.db.Delete(clockMasterLatestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset master clock frames")
	}

	return nil
}

func (p *PebbleClockStore) ResetDataClockFrames(filter []byte) error {
	if err := p.db.DeleteRange(
		clockDataFrameKey(filter, 0),
		clockDataFrameKey(filter, 200000),
	); err != nil {
		return errors.Wrap(err, "reset data clock frames")
	}

	if err := p.db.Delete(clockDataEarliestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset data clock frames")
	}
	if err := p.db.Delete(clockDataLatestIndex(filter)); err != nil {
		return errors.Wrap(err, "reset data clock frames")
	}

	return nil
}

func (p *PebbleClockStore) Compact(
	masterFilter []byte,
	dataFilter []byte,
) error {
	if masterFilter != nil {
		if err := p.db.Compact(
			clockMasterFrameKey(masterFilter, 0),
			clockMasterFrameKey(masterFilter, 1000000),
			true,
		); err != nil {
			return errors.Wrap(err, "compact")
		}
	}

	// If this node has been around since the early days, this is going to free
	// up a lot of cruft.
	if err := p.db.DeleteRange(
		clockDataCandidateFrameKey(
			make([]byte, 32),
			0,
			make([]byte, 32),
			make([]byte, 32),
		),
		clockDataCandidateFrameKey(
			bytes.Repeat([]byte{0xff}, 32),
			1000000,
			bytes.Repeat([]byte{0xff}, 32),
			bytes.Repeat([]byte{0xff}, 32),
		),
	); err != nil {
		return errors.Wrap(err, "compact")
	}
	if err := p.db.Compact(
		clockDataCandidateFrameKey(
			make([]byte, 32),
			0,
			make([]byte, 32),
			make([]byte, 32),
		),
		clockDataCandidateFrameKey(
			bytes.Repeat([]byte{0xff}, 32),
			1000000,
			bytes.Repeat([]byte{0xff}, 32),
			bytes.Repeat([]byte{0xff}, 32),
		),
		true,
	); err != nil {
		return errors.Wrap(err, "compact")
	}

	if dataFilter != nil {
		if err := p.db.Compact(
			dataProofMetadataKey(
				dataFilter,
				make([]byte, 74),
			),
			dataProofMetadataKey(
				dataFilter,
				bytes.Repeat([]byte{0xff}, 74),
			),
			true,
		); err != nil {
			return errors.Wrap(err, "compact")
		}

		if err := p.db.Compact(
			dataProofInclusionKey(
				dataFilter,
				make([]byte, 74),
				0,
			),
			dataProofInclusionKey(
				dataFilter,
				bytes.Repeat([]byte{0xff}, 74),
				20000,
			),
			true,
		); err != nil {
			return errors.Wrap(err, "compact")
		}

		if err := p.db.DeleteRange(
			clockDataCandidateFrameKey(
				dataFilter,
				0,
				make([]byte, 32),
				make([]byte, 32),
			),
			clockDataCandidateFrameKey(
				dataFilter,
				1000000,
				bytes.Repeat([]byte{0xff}, 32),
				bytes.Repeat([]byte{0xff}, 32),
			),
		); err != nil {
			return errors.Wrap(err, "compact")
		}

		if err := p.db.Compact(
			clockDataFrameKey(dataFilter, 0),
			clockDataFrameKey(dataFilter, 1000000),
			true,
		); err != nil {
			return errors.Wrap(err, "compact")
		}

		if err := p.db.Compact(
			clockDataCandidateFrameKey(
				dataFilter,
				0,
				make([]byte, 32),
				make([]byte, 32),
			),
			clockDataCandidateFrameKey(
				dataFilter,
				1000000,
				bytes.Repeat([]byte{0xff}, 32),
				bytes.Repeat([]byte{0xff}, 32),
			),
			true,
		); err != nil {
			return errors.Wrap(err, "compact")
		}

		if err := p.db.Compact(
			clockDataParentIndexKey(
				dataFilter,
				0,
				make([]byte, 32),
			),
			clockDataParentIndexKey(
				dataFilter,
				1000000,
				bytes.Repeat([]byte{0xff}, 32),
			),
			true,
		); err != nil {
			return errors.Wrap(err, "compact")
		}
	}

	return nil
}

func (p *PebbleClockStore) GetTotalDistance(
	filter []byte,
	frameNumber uint64,
	selector []byte,
) (*big.Int, error) {
	value, closer, err := p.db.Get(
		clockDataTotalDistanceKey(filter, frameNumber, selector),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, errors.Wrap(err, "get total distance")
	}

	defer closer.Close()
	dist := new(big.Int).SetBytes(value)

	return dist, nil
}

func (p *PebbleClockStore) SetTotalDistance(
	filter []byte,
	frameNumber uint64,
	selector []byte,
	totalDistance *big.Int,
) error {
	err := p.db.Set(
		clockDataTotalDistanceKey(filter, frameNumber, selector),
		totalDistance.Bytes(),
	)

	return errors.Wrap(err, "set total distance")
}
