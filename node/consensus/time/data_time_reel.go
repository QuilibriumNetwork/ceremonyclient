package time

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"sort"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
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
	selector       *big.Int
	parentSelector *big.Int
}

type DataTimeReel struct {
	rwMutex sync.RWMutex
	running bool

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
	lruFrames             *lru.Cache[string, string]
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

	cache, err := lru.New[string, string](10000)
	if err != nil {
		panic(err)
	}

	return &DataTimeReel{
		running:               false,
		logger:                logger,
		filter:                filter,
		engineConfig:          engineConfig,
		clockStore:            clockStore,
		frameProver:           frameProver,
		origin:                origin,
		initialInclusionProof: initialInclusionProof,
		initialProverKeys:     initialProverKeys,
		lruFrames:             cache,
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
		d.headDistance = big.NewInt(0)
	} else {
		d.head = frame
		if err != nil {
			panic(err)
		}
		d.proverTrie = trie
		d.headDistance, err = d.GetDistance(frame)
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
	if !d.running {
		return nil
	}

	d.logger.Debug(
		"insert frame",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
	)

	if d.lruFrames.Contains(string(frame.Output[:64])) {
		return nil
	}

	d.lruFrames.Add(string(frame.Output[:64]), string(frame.ParentSelector))

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
	d.running = true
	for {
		select {
		case frame := <-d.frames:
			d.logger.Debug(
				"processing frame",
				zap.Uint64("frame_number", frame.FrameNumber),
				zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
				zap.Uint64("head_number", d.head.FrameNumber),
				zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
			)
			// Most common scenario: in order – new frame is higher number
			if d.head.FrameNumber < frame.FrameNumber {
				d.logger.Debug("frame is higher")

				parent := new(big.Int).SetBytes(frame.ParentSelector)
				selector, err := frame.GetSelector()
				if err != nil {
					panic(err)
				}

				distance, err := d.GetDistance(frame)
				if err != nil {
					d.logger.Debug("no master, add pending")

					// If the frame arrived ahead of a master, e.g. the master data is not
					// synced, we'll go ahead and mark it as pending and process it when
					// we can, but if we had a general fault, panic:
					if !errors.Is(err, store.ErrNotFound) {
						panic(err)
					}

					d.addPending(selector, parent, distance, frame)
					d.processPending(d.head, frame)
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
					d.logger.Debug(
						"frame has has gap or is non-descendent, fork choice",
						zap.Bool("has_gap", frame.FrameNumber-d.head.FrameNumber != 1),
						zap.String("parent_selector", parent.Text(16)),
						zap.String("head_selector", headSelector.Text(16)),
					)

					d.forkChoice(frame, distance)
					d.processPending(d.head, frame)
					continue
				}

				// Otherwise set it as the next and process all pending
				d.setHead(frame, distance)
				d.processPending(d.head, frame)
			} else if d.head.FrameNumber == frame.FrameNumber {
				// frames are equivalent, no need to act
				if bytes.Equal(d.head.Output, frame.Output) {
					d.logger.Debug("equivalent frame")
					d.processPending(d.head, frame)
					continue
				}

				distance, err := d.GetDistance(frame)
				if err != nil {
					panic(err)
				}
				d.logger.Debug(
					"frame is same height",
					zap.String("head_distance", d.headDistance.Text(16)),
					zap.String("distance", distance.Text(16)),
				)

				// Optimization: if competing frames share a parent we can short-circuit
				// fork choice
				if bytes.Equal(d.head.ParentSelector, frame.ParentSelector) &&
					distance.Cmp(d.headDistance) < 0 {
					d.logger.Debug(
						"frame shares parent, has shorter distance, short circuit",
					)
					d.totalDistance.Sub(d.totalDistance, d.headDistance)
					d.setHead(frame, distance)
					d.processPending(d.head, frame)
					continue
				}

				// Choose fork
				d.forkChoice(frame, distance)
				d.processPending(d.head, frame)
			} else {
				d.logger.Debug("frame is lower height")

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
					d.logger.Debug("is fork, add pending")

					distance, err := d.GetDistance(frame)
					if err != nil {
						panic(err)
					}

					parent, selector, err := frame.GetParentAndSelector()
					if err != nil {
						panic(err)
					}

					d.addPending(selector, parent, distance, frame)
					d.processPending(d.head, frame)
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
	d.logger.Debug(
		"add pending",
		zap.Uint64("head_frame_number", d.head.FrameNumber),
		zap.Uint64("add_frame_number", frame.FrameNumber),
		zap.String("selector", selector.Text(16)),
		zap.String("parent", parent.Text(16)),
		zap.String("distance", distance.Text(16)),
	)

	if d.head.FrameNumber <= frame.FrameNumber {
		if _, ok := d.pending[frame.FrameNumber]; !ok {
			d.pending[frame.FrameNumber] = []*pendingFrame{}
		}

		// avoid heavy thrashing
		for _, frame := range d.pending[frame.FrameNumber] {
			if frame.selector.Cmp(selector) == 0 {
				d.logger.Debug("exists in pending already")
				return
			}
		}
	}

	// avoid db thrashing
	if existing, err := d.clockStore.GetParentDataClockFrame(
		frame.Filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		true,
	); err != nil && existing == nil {
		d.logger.Debug(
			"not stored yet, save data candidate",
			zap.Uint64("frame_number", frame.FrameNumber),
			zap.String("selector", selector.Text(16)),
			zap.String("parent", parent.Text(16)),
			zap.String("distance", distance.Text(16)),
		)

		txn, err := d.clockStore.NewTransaction()
		if err != nil {
			panic(err)
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
	}

	if d.head.FrameNumber <= frame.FrameNumber {
		d.logger.Debug(
			"accumulate in pending",
			zap.Int("pending_neighbors", len(d.pending[frame.FrameNumber])),
		)

		d.pending[frame.FrameNumber] = append(
			d.pending[frame.FrameNumber],
			&pendingFrame{
				selector:       selector,
				parentSelector: parent,
			},
		)
	}
}

func (d *DataTimeReel) processPending(
	frame *protobufs.ClockFrame,
	lastReceived *protobufs.ClockFrame,
) {
	d.logger.Debug(
		"process pending",
		zap.Int("pending_frame_numbers", len(d.pending)),
	)
	frameNumbers := []uint64{}
	for f := range d.pending {
		frameNumbers = append(frameNumbers, f)
		d.logger.Debug(
			"pending per frame number",
			zap.Uint64("pending_frame_number", f),
			zap.Int("pending_frames", len(d.pending[f])),
		)
	}
	sort.Slice(frameNumbers, func(i, j int) bool {
		return frameNumbers[i] > frameNumbers[j]
	})

	lastSelector, err := lastReceived.GetSelector()
	if err != nil {
		panic(err)
	}

	for _, f := range frameNumbers {
		if f < d.head.FrameNumber {
			delete(d.pending, f)
		}

		nextPending := d.pending[f]
		d.logger.Debug(
			"checking frame set",
			zap.Uint64("pending_frame_number", f),
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		if f < frame.FrameNumber {
			d.logger.Debug(
				"purging frame set",
				zap.Uint64("pending_frame_number", f),
				zap.Uint64("frame_number", frame.FrameNumber),
			)
			delete(d.pending, f)
			continue
		}
		// Pull the next
		for len(nextPending) != 0 {
			d.logger.Debug("try process next")
			next := nextPending[0]
			d.pending[f] = d.pending[f][1:]
			if f == lastReceived.FrameNumber && next.selector.Cmp(lastSelector) == 0 {
				d.pending[f] = append(d.pending[f], next)
				if len(d.pending[f]) == 1 {
					nextPending = nil
				}
				continue
			}

			nextFrame, err := d.clockStore.GetParentDataClockFrame(
				d.filter,
				f,
				next.selector.FillBytes(make([]byte, 32)),
				false,
			)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				panic(err)
			}
			if nextFrame != nil {
				d.logger.Debug("next found, send frame back in")
				go func() {
					d.frames <- nextFrame
				}()
				return
			}

			if len(d.pending[f]) == 0 {
				d.logger.Debug("last next processing, clear list")
				delete(d.pending, f)
				nextPending = nil
			}
		}
	}
}

func (d *DataTimeReel) setHead(frame *protobufs.ClockFrame, distance *big.Int) {
	d.logger.Debug(
		"set frame to head",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
		zap.Uint64("head_number", d.head.FrameNumber),
		zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
	)
	txn, err := d.clockStore.NewTransaction()
	if err != nil {
		panic(err)
	}

	d.logger.Debug(
		"save data",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("distance", distance.Text(16)),
	)

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
		true,
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
		return unknownDistance, errors.Wrap(err, "get distance")
	}

	masterSelector, err := master.GetSelector()
	if err != nil {
		return unknownDistance, errors.Wrap(err, "get distance")
	}

	discriminatorNode :=
		d.proverTrie.FindNearest(masterSelector.FillBytes(make([]byte, 32)))
	discriminator := discriminatorNode.External.Key
	addr, err := frame.GetAddress()
	if err != nil {
		return unknownDistance, errors.Wrap(err, "get distance")
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
	d.logger.Debug(
		"fork choice",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.String("output_tag", hex.EncodeToString(frame.Output[:64])),
		zap.Uint64("head_number", d.head.FrameNumber),
		zap.String("head_output_tag", hex.EncodeToString(d.head.Output[:64])),
	)
	parentSelector, selector, err := frame.GetParentAndSelector()
	if err != nil {
		panic(err)
	}

	leftIndex := d.head
	rightIndex := frame
	leftTotal := new(big.Int).Set(d.headDistance)
	overweight := big.NewInt(0)
	rightTotal := new(big.Int).Set(distance)
	left := d.head.ParentSelector
	right := frame.ParentSelector

	rightReplaySelectors := [][]byte{}

	for rightIndex.FrameNumber > leftIndex.FrameNumber {
		rightReplaySelectors = append(
			append(
				[][]byte{},
				right,
			),
			rightReplaySelectors...,
		)

		rightIndex, err = d.clockStore.GetParentDataClockFrame(
			d.filter,
			rightIndex.FrameNumber-1,
			rightIndex.ParentSelector,
			true,
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

		right = rightIndex.ParentSelector

		rightIndexDistance, err := d.GetDistance(rightIndex)
		if err != nil {
			panic(err)
		}

		// We accumulate right on left when right is longer because we cannot know
		// where the left will lead and don't want it to disadvantage our comparison
		overweight.Add(overweight, rightIndexDistance)
		rightTotal.Add(rightTotal, rightIndexDistance)
	}

	// Walk backwards through the parents, until we find a matching parent
	// selector:
	for !bytes.Equal(left, right) {
		d.logger.Debug(
			"scan backwards",
			zap.String("left_parent", hex.EncodeToString(leftIndex.ParentSelector)),
			zap.String("right_parent", hex.EncodeToString(rightIndex.ParentSelector)),
		)

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
			true,
		)
		if err != nil {
			d.logger.Error(
				"store corruption: a discontinuity has been found in your time reel",
				zap.String(
					"selector",
					hex.EncodeToString(leftIndex.ParentSelector),
				),
				zap.Uint64("frame_number", leftIndex.FrameNumber-1),
			)
			panic(err)
		}

		rightIndex, err = d.clockStore.GetParentDataClockFrame(
			d.filter,
			rightIndex.FrameNumber-1,
			rightIndex.ParentSelector,
			true,
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
	d.logger.Debug("found mutual root")

	frameNumber := rightIndex.FrameNumber

	overweight.Add(overweight, leftTotal)

	// Choose new fork based on lightest distance sub-tree
	if rightTotal.Cmp(overweight) > 0 {
		d.logger.Debug("proposed fork has greater distance",
			zap.String("right_total", rightTotal.Text(16)),
			zap.String("left_total", overweight.Text(16)),
		)
		d.addPending(selector, parentSelector, distance, frame)
		return
	}

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
			false,
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
	d.logger.Debug(
		"set total distance",
		zap.String("total_distance", d.totalDistance.Text(16)),
	)
	go func() {
		d.newFrameCh <- frame
	}()
}

var _ TimeReel = (*DataTimeReel)(nil)
