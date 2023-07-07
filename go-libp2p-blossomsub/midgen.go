package blossomsub

import (
	"sync"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

// msgIDGenerator handles computing IDs for msgs
// It allows setting custom generators(MsgIdFunction) per bitmask
type msgIDGenerator struct {
	Default MsgIdFunction

	bitmaskGensLk sync.RWMutex
	bitmaskGens   map[string]MsgIdFunction
}

func newMsgIdGenerator() *msgIDGenerator {
	return &msgIDGenerator{
		Default:     DefaultMsgIdFn,
		bitmaskGens: make(map[string]MsgIdFunction),
	}
}

// Set sets custom id generator(MsgIdFunction) for bitmask.
func (m *msgIDGenerator) Set(bitmask []byte, gen MsgIdFunction) {
	m.bitmaskGensLk.Lock()
	m.bitmaskGens[string(bitmask)] = gen
	m.bitmaskGensLk.Unlock()
}

// ID computes ID for the msg or short-circuits with the cached value.
func (m *msgIDGenerator) ID(msg *Message) string {
	if msg.ID != "" {
		return msg.ID
	}

	msg.ID = m.RawID(msg.Message)
	return msg.ID
}

// RawID computes ID for the proto 'msg'.
func (m *msgIDGenerator) RawID(msg *pb.Message) string {
	m.bitmaskGensLk.RLock()
	gen, ok := m.bitmaskGens[string(msg.GetBitmask())]
	m.bitmaskGensLk.RUnlock()
	if !ok {
		gen = m.Default
	}

	return gen(msg)
}
