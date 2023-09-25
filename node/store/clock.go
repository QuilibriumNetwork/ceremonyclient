package store

import (
	"encoding/binary"

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
	) (*protobufs.ClockFrame, *tries.RollingFrecencyCritbitTrie, error)
	RangeDataClockFrames(
		filter []byte,
		startFrameNumber uint64,
		endFrameNumber uint64,
	) (*PebbleClockIterator, error)
	PutDataClockFrame(
		frame *protobufs.ClockFrame,
		proverTrie *tries.RollingFrecencyCritbitTrie,
		txn Transaction,
	) error
	PutCandidateDataClockFrame(
		parentSelector []byte,
		distance []byte,
		selector []byte,
		frame *protobufs.ClockFrame,
		txn Transaction,
	) error
	GetCandidateDataClockFrames(
		filter []byte,
		frameNumber uint64,
	) ([]*protobufs.ClockFrame, error)
	GetParentDataClockFrame(
		filter []byte,
		frameNumber uint64,
		parentSelector []byte,
	) (*protobufs.ClockFrame, error)
	RangeCandidateDataClockFrames(
		filter []byte,
		parent []byte,
		frameNumber uint64,
	) (*PebbleCandidateClockIterator, error)
	GetLeadingCandidateDataClockFrame(
		filter []byte,
		parent []byte,
		frameNumber uint64,
	) (*protobufs.ClockFrame, error)
}

type PebbleClockStore struct {
	db     *pebble.DB
	logger *zap.Logger
}

var _ ClockStore = (*PebbleClockStore)(nil)

type PebbleMasterClockIterator struct {
	i *pebble.Iterator
}

type PebbleClockIterator struct {
	i *pebble.Iterator
}

type PebbleCandidateClockIterator struct {
	i *pebble.Iterator
}

var _ Iterator[*protobufs.ClockFrame] = (*PebbleMasterClockIterator)(nil)
var _ Iterator[*protobufs.ClockFrame] = (*PebbleClockIterator)(nil)
var _ Iterator[*protobufs.ClockFrame] = (*PebbleCandidateClockIterator)(nil)

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
	frame.Filter = filter

	if len(value) < 521 {
		return nil, errors.Wrap(
			ErrInvalidData,
			"get master clock frame iterator value",
		)
	}

	frame.Difficulty = binary.BigEndian.Uint32(value[:4])
	frame.Input = value[4 : len(value)-516]
	frame.Output = value[len(value)-516:]

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Input[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "get master clock frame iterator value")
	}

	frame.ParentSelector = parent.Bytes()

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

func (p *PebbleClockIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleClockIterator) Value() (*protobufs.ClockFrame, error) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.ClockFrame{}
	if err := proto.Unmarshal(value, frame); err != nil {
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

func (p *PebbleCandidateClockIterator) First() bool {
	return p.i.First()
}

func (p *PebbleCandidateClockIterator) Next() bool {
	return p.i.Next()
}

func (p *PebbleCandidateClockIterator) Valid() bool {
	return p.i.Valid()
}

func (p *PebbleCandidateClockIterator) Value() (*protobufs.ClockFrame, error) {
	if !p.i.Valid() {
		return nil, ErrNotFound
	}

	value := p.i.Value()
	frame := &protobufs.ClockFrame{}
	if err := proto.Unmarshal(value, frame); err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"get candidate clock frame iterator value",
		)
	}

	return frame, nil
}

func (p *PebbleCandidateClockIterator) Close() error {
	return errors.Wrap(p.i.Close(), "closing candidate clock frame iterator")
}

func NewPebbleClockStore(db *pebble.DB, logger *zap.Logger) *PebbleClockStore {
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
const CLOCK_MASTER_FRAME_INDEX_EARLIEST = 0x10 | CLOCK_MASTER_FRAME_DATA
const CLOCK_MASTER_FRAME_INDEX_LATEST = 0x20 | CLOCK_MASTER_FRAME_DATA
const CLOCK_MASTER_FRAME_INDEX_PARENT = 0x30 | CLOCK_MASTER_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_EARLIEST = 0x10 | CLOCK_DATA_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_LATEST = 0x20 | CLOCK_DATA_FRAME_DATA
const CLOCK_DATA_FRAME_INDEX_PARENT = 0x30 | CLOCK_DATA_FRAME_DATA

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

	return binary.BigEndian.Uint64(key[2:10]), key[10:], nil
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
		selector,
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

func (p *PebbleClockStore) NewTransaction() (Transaction, error) {
	return &PebbleTransaction{
		b: p.db.NewBatch(),
	}, nil
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

	frame.ParentSelector = parent.Bytes()

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

	iter := p.db.NewIter(&pebble.IterOptions{
		LowerBound: clockMasterFrameKey(filter, startFrameNumber),
		UpperBound: clockMasterFrameKey(filter, endFrameNumber),
	})

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
) (*protobufs.ClockFrame, *tries.RollingFrecencyCritbitTrie, error) {
	value, closer, err := p.db.Get(clockDataFrameKey(filter, frameNumber))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil, ErrNotFound
		}

		return nil, nil, errors.Wrap(err, "get data clock frame")
	}

	defer closer.Close()
	frame := &protobufs.ClockFrame{}
	if err := proto.Unmarshal(value, frame); err != nil {
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
	frame, _, err := p.GetDataClockFrame(filter, frameNumber)
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
	frame, _, err := p.GetDataClockFrame(filter, frameNumber)
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

// GetLeadingCandidateDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetLeadingCandidateDataClockFrame(
	filter []byte,
	parent []byte,
	frameNumber uint64,
) (*protobufs.ClockFrame, error) {
	iter, err := p.RangeCandidateDataClockFrames(filter, parent, frameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "get leading candidate data clock frame")
	}

	if !iter.First() {
		return nil, ErrNotFound
	}

	defer iter.Close()
	frame, err := iter.Value()
	return frame, errors.Wrap(err, "get leading candidate data clock frame")
}

// GetParentDataClockFrame implements ClockStore.
func (p *PebbleClockStore) GetParentDataClockFrame(
	filter []byte,
	frameNumber uint64,
	parentSelector []byte,
) (*protobufs.ClockFrame, error) {
	data, closer, err := p.db.Get(
		clockDataParentIndexKey(filter, frameNumber, parentSelector),
	)
	if err != nil {
		return nil, errors.Wrap(err, "get parent data clock frame")
	}

	parent := &protobufs.ClockFrame{}
	if err := proto.Unmarshal(data, parent); err != nil {
		return nil, errors.Wrap(err, "get parent data clock frame")
	}

	if closer != nil {
		closer.Close()
	}

	return parent, nil
}

// PutCandidateDataClockFrame implements ClockStore.
func (p *PebbleClockStore) PutCandidateDataClockFrame(
	parentSelector []byte,
	distance []byte,
	selector []byte,
	frame *protobufs.ClockFrame,
	txn Transaction,
) error {
	data, err := proto.Marshal(frame)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"put candidate data clock frame",
		)
	}

	if err = txn.Set(
		clockDataCandidateFrameKey(
			frame.Filter,
			frame.FrameNumber,
			frame.ParentSelector,
			distance,
		),
		data,
	); err != nil {
		return errors.Wrap(err, "put candidate data clock frame")
	}

	if err = txn.Set(
		clockDataParentIndexKey(
			frame.Filter,
			frame.FrameNumber,
			selector,
		),
		data,
	); err != nil {
		return errors.Wrap(err, "put candidate data clock frame")
	}

	return nil
}

// PutDataClockFrame implements ClockStore.
func (p *PebbleClockStore) PutDataClockFrame(
	frame *protobufs.ClockFrame,
	proverTrie *tries.RollingFrecencyCritbitTrie,
	txn Transaction,
) error {
	data, err := proto.Marshal(frame)
	if err != nil {
		return errors.Wrap(
			errors.Wrap(err, ErrInvalidData.Error()),
			"put data clock frame",
		)
	}

	frameNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(frameNumberBytes, frame.FrameNumber)

	if err = txn.Set(
		clockDataFrameKey(frame.Filter, frame.FrameNumber),
		data,
	); err != nil {
		return errors.Wrap(err, "put data clock frame")
	}

	proverData, err := proverTrie.Serialize()
	if err != nil {
		return errors.Wrap(err, "put data clock frame")
	}

	if err = txn.Set(
		clockProverTrieKey(frame.Filter, frame.FrameNumber),
		proverData,
	); err != nil {
		return errors.Wrap(err, "put data clock frame")
	}

	_, closer, err := p.db.Get(clockDataEarliestIndex(frame.Filter))
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return errors.Wrap(err, "put data clock frame")
		}

		if err = txn.Set(
			clockDataEarliestIndex(frame.Filter),
			frameNumberBytes,
		); err != nil {
			return errors.Wrap(err, "put data clock frame")
		}
	}

	if err == nil && closer != nil {
		closer.Close()
	}

	if err = txn.Set(
		clockDataLatestIndex(frame.Filter),
		frameNumberBytes,
	); err != nil {
		return errors.Wrap(err, "put data clock frame")
	}

	return nil
}

// GetCandidateDataClockFrames implements ClockStore.
// Distance is 32-byte aligned, so we just use a 0x00 * 32 -> 0xff * 32 range
func (p *PebbleClockStore) GetCandidateDataClockFrames(
	filter []byte,
	frameNumber uint64,
) ([]*protobufs.ClockFrame, error) {
	iter := p.db.NewIter(&pebble.IterOptions{
		LowerBound: clockDataCandidateFrameKey(
			filter,
			frameNumber,
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		),
		UpperBound: clockDataCandidateFrameKey(
			filter,
			frameNumber,
			[]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
			[]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
		),
	})

	frames := []*protobufs.ClockFrame{}
	i := &PebbleCandidateClockIterator{i: iter}

	for i.First(); i.Valid(); i.Next() {
		value, err := i.Value()
		if err != nil {
			return nil, errors.Wrap(err, "get candidate data clock frames")
		}

		frames = append(frames, value)
	}

	if err := i.Close(); err != nil {
		return nil, errors.Wrap(err, "get candidate data clock frames")
	}

	return frames, nil
}

// RangeCandidateDataClockFrames implements ClockStore.
// Distance is 32-byte aligned, so we just use a 0x00 * 32 -> 0xff * 32 range
func (p *PebbleClockStore) RangeCandidateDataClockFrames(
	filter []byte,
	parent []byte,
	frameNumber uint64,
) (*PebbleCandidateClockIterator, error) {
	iter := p.db.NewIter(&pebble.IterOptions{
		LowerBound: clockDataCandidateFrameKey(
			filter,
			frameNumber,
			parent,
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		),
		UpperBound: clockDataCandidateFrameKey(
			filter,
			frameNumber,
			parent,
			[]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
		),
	})

	return &PebbleCandidateClockIterator{i: iter}, nil
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

	iter := p.db.NewIter(&pebble.IterOptions{
		LowerBound: clockDataFrameKey(filter, startFrameNumber),
		UpperBound: clockDataFrameKey(filter, endFrameNumber),
	})

	return &PebbleClockIterator{i: iter}, nil
}
