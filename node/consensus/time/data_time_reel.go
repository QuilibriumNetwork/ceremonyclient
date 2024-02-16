package time

import (
	"bytes"
	"math/big"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

var allBitmaskFilter = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

var unknownDistance = new(big.Int).SetBytes([]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
})

type pendingFrame struct {
	parentSelector *big.Int
	distance       *big.Int
}

type DataTimeReel struct {
	rwMutex sync.RWMutex

	filter         []byte
	engineConfig   *config.EngineConfig
	logger         *zap.Logger
	clockStore     store.ClockStore
	frameProver    crypto.FrameProver
	parentTimeReel TimeReel

	origin                []byte
	initialInclusionProof *crypto.InclusionAggregateProof
	initialProverKeys     [][]byte
	head                  *protobufs.ClockFrame
	totalDistance         *big.Int
	headDistance          *big.Int
	proverTrie            *tries.RollingFrecencyCritbitTrie
	pending               map[uint64][]*pendingFrame
	incompleteForks       map[uint64][]*pendingFrame
	frames                chan *protobufs.ClockFrame
	newFrameCh            chan *protobufs.ClockFrame
	badFrameCh            chan *protobufs.ClockFrame
	done                  chan bool
}

func NewDataTimeReel(
	filter []byte,
	logger *zap.Logger,
	clockStore store.ClockStore,
	engineConfig *config.EngineConfig,
	frameProver crypto.FrameProver,
	origin []byte,
	initialInclusionProof *crypto.InclusionAggregateProof,
	initialProverKeys [][]byte,
) *DataTimeReel {
	if filter == nil {
		panic("filter is nil")
	}

	if logger == nil {
		panic("logger is nil")
	}

	if clockStore == nil {
		panic("clock store is nil")
	}

	if engineConfig == nil {
		panic("engine config is nil")
	}

	if frameProver == nil {
		panic("frame prover is nil")
	}

	return &DataTimeReel{
		logger:                logger,
		filter:                filter,
		engineConfig:          engineConfig,
		clockStore:            clockStore,
		frameProver:           frameProver,
		origin:                origin,
		initialInclusionProof: initialInclusionProof,
		initialProverKeys:     initialProverKeys,
		pending:               make(map[uint64][]*pendingFrame),
		incompleteForks:       make(map[uint64][]*pendingFrame),
		frames:                make(chan *protobufs.ClockFrame),
		newFrameCh:            make(chan *protobufs.ClockFrame),
		badFrameCh:            make(chan *protobufs.ClockFrame),
		done:                  make(chan bool),
	}
}

func (d *DataTimeReel) Start() error {
	trie := &tries.RollingFrecencyCritbitTrie{}
	frame, err := d.clockStore.GetLatestDataClockFrame(d.filter, trie)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		panic(err)
	}

	if frame == nil {
		d.head, d.proverTrie = d.createGenesisFrame()
		d.totalDistance = big.NewInt(0)
	} else {
		d.head = frame
		d.proverTrie = trie
		d.totalDistance = d.getTotalDistance(frame)
	}

	go d.runLoop()

	return nil
}

func (d *DataTimeReel) Head() (*protobufs.ClockFrame, error) {
	return d.head, nil
}

// Insert enqueues a structurally valid frame into the time reel. If the frame
// is the next one in sequence, it advances the reel head forward and emits a
// new frame on the new frame channel.
func (d *DataTimeReel) Insert(frame *protobufs.ClockFrame) error {
	go func() {
		d.frames <- frame
	}()

	return nil
}

func (d *DataTimeReel) GetFrameProverTrie() *tries.RollingFrecencyCritbitTrie {
	return d.proverTrie
}

func (d *DataTimeReel) NewFrameCh() <-chan *protobufs.ClockFrame {
	return d.newFrameCh
}

func (d *DataTimeReel) BadFrameCh() <-chan *protobufs.ClockFrame {
	return d.badFrameCh
}

func (d *DataTimeReel) Stop() {
	d.done <- true
}

func (d *DataTimeReel) createGenesisFrame() (
	*protobufs.ClockFrame,
	*tries.RollingFrecencyCritbitTrie,
) {
	if d.origin == nil {
		panic("origin is nil")
	}

	if d.initialInclusionProof == nil {
		panic("initial inclusion proof is nil")
	}

	if d.initialProverKeys == nil {
		panic("initial prover keys is nil")
	}

	difficulty := d.engineConfig.Difficulty
	if difficulty == 0 {
		difficulty = 10000
	}

	frame, trie, err := d.frameProver.CreateDataGenesisFrame(
		d.filter,
		d.origin,
		difficulty,
		d.initialInclusionProof,
		d.initialProverKeys,
		true,
	)
	if err != nil {
		panic(err)
	}

	txn, err := d.clockStore.NewTransaction()
	if err != nil {
		panic(err)
	}

	if err := d.clockStore.PutDataClockFrame(
		frame,
		trie,
		txn,
		false,
	); err != nil {
		panic(err)
	}

	if err := txn.Commit(); err != nil {
		panic(err)
	}

	return frame, trie
}

// Main data consensus loop
func (d *DataTimeReel) runLoop() {
	for {
		select {
		case frame := <-d.frames:
			// Most common scenario: in order – new frame is higher number
			if d.head.FrameNumber < frame.FrameNumber {
				parent := new(big.Int).SetBytes(frame.ParentSelector)
				selector, err := frame.GetSelector()
				if err != nil {
					panic(err)
				}

				distance, err := d.GetDistance(frame)
				if err != nil {
					// If the frame arrived ahead of a master, e.g. the master data is not
					// synced, we'll go ahead and mark it as pending and process it when
					// we can, but if we had a general fault, panic:
					if !errors.Is(err, store.ErrNotFound) {
						panic(err)
					}

					d.addPending(selector, parent, unknownDistance, frame)
					continue
				}

				headSelector, err := d.head.GetSelector()
				if err != nil {
					panic(err)
				}

				// If the frame has a gap from the head or is not descendent, mark it as
				// pending:
				if frame.FrameNumber-d.head.FrameNumber != 1 ||
					parent.Cmp(headSelector) != 0 {
					d.addPending(selector, parent, distance, frame)
					continue
				}

				// Otherwise set it as the next and process all pending
				d.setHead(frame, distance)
				d.processPending(frame)
			} else if d.head.FrameNumber == frame.FrameNumber {
				// frames are equivalent, no need to act
				if bytes.Equal(d.head.Output, frame.Output) {
					continue
				}

				distance, err := d.GetDistance(frame)
				if err != nil {
					panic(err)
				}

				// Optimization: if competing frames share a parent we can short-circuit
				// fork choice
				if bytes.Equal(d.head.ParentSelector, frame.ParentSelector) &&
					distance.Cmp(d.headDistance) < 0 {
					d.totalDistance.Sub(d.totalDistance, d.headDistance)
					d.setHead(frame, distance)
					d.processPending(d.head)
					continue
				}

				// Choose fork
				d.forkChoice(frame, distance)
				d.processPending(d.head)
			} else {
				// tag: dusk – we should have some kind of check here to avoid brutal
				// thrashing
				existing, _, err := d.clockStore.GetDataClockFrame(
					d.filter,
					frame.FrameNumber,
				)
				if err != nil {
					// if this returns an error it's either not found (which shouldn't
					// happen without corruption) or pebble is borked, either way, panic
					panic(err)
				}

				// It's a fork, but it's behind. We need to stash it until it catches
				// up (or dies off)
				if !bytes.Equal(existing.Output, frame.Output) {
					distance, err := d.GetDistance(frame)
					if err != nil {
						panic(err)
					}

					parent, selector, err := frame.GetParentAndSelector()
					if err != nil {
						panic(err)
					}

					d.addPending(selector, parent, distance, frame)
					d.processPending(d.head)
				}
			}
		case <-d.done:
			return
		}
	}
}

func (d *DataTimeReel) addPending(
	selector *big.Int,
	parent *big.Int,
	distance *big.Int,
	frame *protobufs.ClockFrame,
) {
	if _, ok := d.pending[frame.FrameNumber]; !ok {
		d.pending[frame.FrameNumber] = []*pendingFrame{}
	}

	txn, err := d.clockStore.NewTransaction()
	if err != nil {
		panic(err)
	}

	if distance.Cmp(unknownDistance) == 0 {
		distance = new(big.Int).Set(unknownDistance)
		distance.Sub(distance, big.NewInt(int64(len(d.pending[frame.FrameNumber]))))
	}

	err = d.clockStore.PutCandidateDataClockFrame(
		parent.FillBytes(make([]byte, 32)),
		distance.FillBytes(make([]byte, 32)),
		selector.FillBytes(make([]byte, 32)),
		frame,
		txn,
	)
	if err != nil {
		txn.Abort()
		panic(err)
	}

	if err = txn.Commit(); err != nil {
		panic(err)
	}

	d.pending[frame.FrameNumber] = append(
		d.pending[frame.FrameNumber],
		&pendingFrame{
			parentSelector: parent,
			distance:       distance,
		},
	)
}

func (d *DataTimeReel) processPending(frame *protobufs.ClockFrame) {
	neighbors := false
	// Flush the current pending frames
	neighborPending, ok := d.pending[frame.FrameNumber]
	for ok && neighborPending != nil {
		next := neighborPending[0]
		d.pending[frame.FrameNumber] =
			d.pending[frame.FrameNumber][1:]
		if len(d.pending[frame.FrameNumber]) == 0 {
			delete(d.pending, frame.FrameNumber)
		}

		nextFrame, err := d.clockStore.GetCandidateDataClockFrame(
			d.filter,
			frame.FrameNumber,
			next.parentSelector.FillBytes(make([]byte, 32)),
			next.distance.FillBytes(make([]byte, 32)),
		)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			panic(err)
		}
		if nextFrame != nil {
			neighbors = true
			go func() {
				d.frames <- nextFrame
			}()
		}
		neighborPending, ok = d.pending[frame.FrameNumber]
	}

	above := false
	if !neighbors {
		// Pull the next
		nextPending, ok := d.pending[frame.FrameNumber+1]
		if ok {
			next := nextPending[0]
			d.pending[frame.FrameNumber+1] =
				d.pending[frame.FrameNumber+1][1:]
			if len(d.pending[frame.FrameNumber+1]) == 0 {
				delete(d.pending, frame.FrameNumber+1)
			}

			nextFrame, err := d.clockStore.GetCandidateDataClockFrame(
				d.filter,
				frame.FrameNumber+1,
				next.parentSelector.FillBytes(make([]byte, 32)),
				next.distance.FillBytes(make([]byte, 32)),
			)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				panic(err)
			}
			if nextFrame != nil {
				above = true
				go func() {
					d.frames <- nextFrame
				}()
			}
		}
	}

	if !above {
		// Pull below
		min := frame.FrameNumber
		for k := range d.pending {
			if k < min {
				min = k
			}
		}
		if min == frame.FrameNumber {
			return
		}
		nextPending, ok := d.pending[min]
		if ok {
			next := nextPending[0]
			d.pending[min] =
				d.pending[min][1:]
			if len(d.pending[min]) == 0 {
				delete(d.pending, min)
			}

			nextFrame, err := d.clockStore.GetCandidateDataClockFrame(
				d.filter,
				min,
				next.parentSelector.FillBytes(make([]byte, 32)),
				next.distance.FillBytes(make([]byte, 32)),
			)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				panic(err)
			}
			if nextFrame != nil {
				go func() {
					d.frames <- nextFrame
				}()
			}
		}
	}
}

func (d *DataTimeReel) setHead(frame *protobufs.ClockFrame, distance *big.Int) {
	txn, err := d.clockStore.NewTransaction()
	if err != nil {
		panic(err)
	}

	if err := d.clockStore.PutDataClockFrame(
		frame,
		d.proverTrie,
		txn,
		false,
	); err != nil {
		panic(err)
	}

	if err = txn.Commit(); err != nil {
		panic(err)
	}

	d.head = frame
	d.totalDistance.Add(d.totalDistance, distance)
	d.headDistance = distance
	go func() {
		d.newFrameCh <- frame
	}()
}

// tag: dusk – store the distance with the frame
func (d *DataTimeReel) getTotalDistance(frame *protobufs.ClockFrame) *big.Int {
	total, err := d.GetDistance(frame)
	if err != nil {
		panic(err)
	}

	for index := frame; err == nil &&
		index.FrameNumber > 0; index, err = d.clockStore.GetParentDataClockFrame(
		d.filter,
		index.FrameNumber-1,
		index.ParentSelector,
	) {
		distance, err := d.GetDistance(index)
		if err != nil {
			panic(err)
		}

		total.Add(total, distance)
	}

	return total
}

func (d *DataTimeReel) GetDistance(frame *protobufs.ClockFrame) (
	*big.Int,
	error,
) {
	// tag: equinox – master filter changes
	master, err := d.clockStore.GetMasterClockFrame(
		allBitmaskFilter,
		frame.FrameNumber)
	if err != nil {
		return nil, errors.Wrap(err, "get distance")
	}

	masterSelector, err := master.GetSelector()
	if err != nil {
		return nil, errors.Wrap(err, "get distance")
	}

	discriminatorNode :=
		d.proverTrie.FindNearest(masterSelector.FillBytes(make([]byte, 32)))
	discriminator := discriminatorNode.External.Key
	addr, err := frame.GetAddress()
	if err != nil {
		return nil, errors.Wrap(err, "get distance")
	}
	distance := new(big.Int).Sub(
		new(big.Int).SetBytes(discriminator),
		new(big.Int).SetBytes(addr),
	)
	distance.Abs(distance)

	return distance, nil
}

func (d *DataTimeReel) forkChoice(
	frame *protobufs.ClockFrame,
	distance *big.Int,
) {
	parentSelector, selector, err := frame.GetParentAndSelector()
	if err != nil {
		panic(err)
	}

	leftIndex := d.head
	rightIndex := frame
	leftTotal := new(big.Int).Set(d.headDistance)
	rightTotal := new(big.Int).Set(distance)
	left := d.head.ParentSelector
	right := frame.ParentSelector

	rightReplaySelectors := [][]byte{}

	// Walk backwards through the parents, until we find a matching parent
	// selector:
	for !bytes.Equal(left, right) {
		rightReplaySelectors = append(
			append(
				[][]byte{},
				right,
			),
			rightReplaySelectors...,
		)
		leftIndex, err = d.clockStore.GetParentDataClockFrame(
			d.filter,
			leftIndex.FrameNumber-1,
			leftIndex.ParentSelector,
		)
		if err != nil {
			panic(err)
		}

		rightIndex, err = d.clockStore.GetParentDataClockFrame(
			d.filter,
			rightIndex.FrameNumber-1,
			rightIndex.ParentSelector,
		)
		if err != nil {
			// If lineage cannot be verified, set it for later
			if errors.Is(err, store.ErrNotFound) {
				d.addPending(selector, parentSelector, distance, frame)
				return
			} else {
				panic(err)
			}
		}

		left = leftIndex.ParentSelector
		right = rightIndex.ParentSelector
		leftIndexDistance, err := d.GetDistance(leftIndex)
		if err != nil {
			panic(err)
		}

		rightIndexDistance, err := d.GetDistance(rightIndex)
		if err != nil {
			panic(err)
		}

		leftTotal.Add(leftTotal, leftIndexDistance)
		rightTotal.Add(rightTotal, rightIndexDistance)
	}

	frameNumber := rightIndex.FrameNumber

	// Choose new fork based on lightest distance sub-tree
	if rightTotal.Cmp(leftTotal) < 0 {
		for {
			if len(rightReplaySelectors) == 0 {
				break
			}
			next := rightReplaySelectors[0]
			rightReplaySelectors =
				rightReplaySelectors[1:]

			rightIndex, err = d.clockStore.GetParentDataClockFrame(
				d.filter,
				frameNumber,
				next,
			)
			if err != nil {
				panic(err)
			}

			txn, err := d.clockStore.NewTransaction()
			if err != nil {
				panic(err)
			}

			if err := d.clockStore.PutDataClockFrame(
				rightIndex,
				d.proverTrie,
				txn,
				false,
			); err != nil {
				panic(err)
			}

			if err = txn.Commit(); err != nil {
				panic(err)
			}

			frameNumber++
		}

		txn, err := d.clockStore.NewTransaction()
		if err != nil {
			panic(err)
		}

		if err := d.clockStore.PutDataClockFrame(
			frame,
			d.proverTrie,
			txn,
			false,
		); err != nil {
			panic(err)
		}

		if err = txn.Commit(); err != nil {
			panic(err)
		}

		d.head = frame
		d.totalDistance.Sub(d.totalDistance, leftTotal)
		d.totalDistance.Add(d.totalDistance, rightTotal)
		d.headDistance = distance
		go func() {
			d.newFrameCh <- frame
		}()
	}
}

var _ TimeReel = (*DataTimeReel)(nil)
