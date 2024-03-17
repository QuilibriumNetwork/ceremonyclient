package time

import (
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type TimeReel interface {
	Start() error
	Stop()
	Insert(frame *protobufs.ClockFrame, isSync bool) error
	Head() (*protobufs.ClockFrame, error)
	NewFrameCh() <-chan *protobufs.ClockFrame
	BadFrameCh() <-chan *protobufs.ClockFrame
}
