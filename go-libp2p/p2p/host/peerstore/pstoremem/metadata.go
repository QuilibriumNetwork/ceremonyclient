package pstoremem

import (
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	pstore "github.com/libp2p/go-libp2p/core/peerstore"
)

type memoryPeerMetadata struct {
	// store other data, like versions
	ds     map[peer.ID]map[string]interface{}
	dslock sync.RWMutex
}

var _ pstore.PeerMetadata = (*memoryPeerMetadata)(nil)

func NewPeerMetadata() *memoryPeerMetadata {
	return &memoryPeerMetadata{
		ds: make(map[peer.ID]map[string]interface{}),
	}
}

func (ps *memoryPeerMetadata) Put(p peer.ID, key string, val interface{}) error {
	ps.dslock.Lock()

	m, ok := ps.ds[p]
	if !ok {
		m = make(map[string]interface{})
		ps.ds[p] = m
	}
	m[key] = val
	ps.dslock.Unlock()
	return nil
}

func (ps *memoryPeerMetadata) Get(p peer.ID, key string) (interface{}, error) {
	ps.dslock.RLock()

	m, ok := ps.ds[p]
	if !ok {
		ps.dslock.RUnlock()
		return nil, pstore.ErrNotFound
	}
	val, ok := m[key]
	if !ok {
		ps.dslock.RUnlock()
		return nil, pstore.ErrNotFound
	}
	ps.dslock.RUnlock()
	return val, nil
}

func (ps *memoryPeerMetadata) RemovePeer(p peer.ID) {
	ps.dslock.Lock()
	delete(ps.ds, p)
	ps.dslock.Unlock()
}
