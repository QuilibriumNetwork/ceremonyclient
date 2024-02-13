package time

import (
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type MasterTimeReel struct {
	rwMutex sync.RWMutex

	filter       []byte
	engineConfig *config.EngineConfig
	logger       *zap.Logger
	clockStore   store.ClockStore
	frameProver  crypto.FrameProver

	head       *protobufs.ClockFrame
	pending    map[uint64][]*big.Int
	frames     chan *protobufs.ClockFrame
	newFrameCh chan *protobufs.ClockFrame
	badFrameCh chan *protobufs.ClockFrame
	done       chan bool
}

func NewMasterTimeReel(
	logger *zap.Logger,
	clockStore store.ClockStore,
	engineConfig *config.EngineConfig,
	frameProver crypto.FrameProver,
) *MasterTimeReel {
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

	filter, err := hex.DecodeString(engineConfig.Filter)
	if err != nil {
		panic(err)
	}

	return &MasterTimeReel{
		logger:       logger,
		filter:       filter,
		engineConfig: engineConfig,
		clockStore:   clockStore,
		frameProver:  frameProver,
		pending:      make(map[uint64][]*big.Int),
		frames:       make(chan *protobufs.ClockFrame),
		newFrameCh:   make(chan *protobufs.ClockFrame),
		badFrameCh:   make(chan *protobufs.ClockFrame),
		done:         make(chan bool),
	}
}

// Start implements TimeReel.
func (m *MasterTimeReel) Start() error {
	frame, err := m.clockStore.GetLatestMasterClockFrame(m.filter)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		panic(err)
	}

	if frame == nil {
		m.head = m.createGenesisFrame()
	} else {
		m.head = frame
	}

	go m.runLoop()

	return nil
}

// Head implements TimeReel.
func (m *MasterTimeReel) Head() (*protobufs.ClockFrame, error) {
	return m.head, nil
}

// Insert enqueues a structurally valid frame into the time reel. If the frame
// is the next one in sequence, it advances the reel head forward and emits a
// new frame on the new frame channel.
func (m *MasterTimeReel) Insert(frame *protobufs.ClockFrame) error {
	go func() {
		m.frames <- frame
	}()

	return nil
}

// NewFrameCh implements TimeReel.
func (m *MasterTimeReel) NewFrameCh() <-chan *protobufs.ClockFrame {
	return m.newFrameCh
}

func (m *MasterTimeReel) BadFrameCh() <-chan *protobufs.ClockFrame {
	return m.badFrameCh
}

// Stop implements TimeReel.
func (m *MasterTimeReel) Stop() {
	m.done <- true
}

func (m *MasterTimeReel) createGenesisFrame() *protobufs.ClockFrame {
	seed, err := hex.DecodeString(m.engineConfig.GenesisSeed)
	if err != nil {
		panic(errors.New("genesis seed is nil"))
	}

	frame, err := m.frameProver.CreateMasterGenesisFrame(
		m.filter,
		seed,
		m.engineConfig.Difficulty,
	)
	if err != nil {
		panic(err)
	}

	txn, err := m.clockStore.NewTransaction()
	if err != nil {
		panic(err)
	}

	if err = m.clockStore.PutMasterClockFrame(frame, txn); err != nil {
		panic(err)
	}

	if err = txn.Commit(); err != nil {
		panic(err)
	}

	return frame
}

func (m *MasterTimeReel) runLoop() {
	for {
		select {
		case frame := <-m.frames:
			if m.head.FrameNumber < frame.FrameNumber {
				m.logger.Debug(
					"new frame has higher number",
					zap.Uint32("new_frame_number", uint32(frame.FrameNumber)),
					zap.Uint32("frame_number", uint32(m.head.FrameNumber)),
				)
				if frame.FrameNumber-m.head.FrameNumber == 1 {
					parent := new(big.Int).SetBytes(frame.ParentSelector)
					selector, err := m.head.GetSelector()
					if err != nil {
						panic(err)
					}

					// master frames cannot fork, this is invalid
					if parent.Cmp(selector) != 0 {
						m.logger.Debug(
							"invalid parent selector for frame",
							zap.Binary("frame_parent_selector", frame.ParentSelector),
							zap.Binary("actual_parent_selector", selector.FillBytes(
								make([]byte, 32),
							)),
						)
						go func() {
							m.badFrameCh <- frame
						}()
						continue
					}

					txn, err := m.clockStore.NewTransaction()
					if err != nil {
						panic(err)
					}

					if err := m.clockStore.PutMasterClockFrame(frame, txn); err != nil {
						panic(err)
					}

					if err = txn.Commit(); err != nil {
						panic(err)
					}

					m.head = frame
					go func() {
						m.newFrameCh <- frame
					}()
				} else {
					go func() {
						m.frames <- frame
					}()
				}
			} else {
				m.logger.Debug(
					"new frame has same or lower frame number",
					zap.Uint32("new_frame_number", uint32(frame.FrameNumber)),
					zap.Uint32("frame_number", uint32(m.head.FrameNumber)),
				)
				continue
			}
		case <-m.done:
			return
		}
	}
}

var _ TimeReel = (*MasterTimeReel)(nil)
