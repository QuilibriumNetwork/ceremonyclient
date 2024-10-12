package p2p

import (
	"bytes"
	"sync"

	"go.uber.org/zap"
)

type PeerInfoManager interface {
	Start()
	Stop()
	AddPeerInfo(manifest *PeerManifest)
	GetPeerInfo(peerId []byte) *PeerManifest
	GetPeerMap() map[string]*PeerManifest
	GetPeersBySpeed() [][]byte
}

type Capability struct {
	ProtocolIdentifier uint32
	AdditionalMetadata []byte
}

type PeerManifest struct {
	PeerId            []byte
	Difficulty        uint32
	DifficultyMetric  int64
	Commit_16Metric   int64
	Commit_128Metric  int64
	Commit_1024Metric int64
	Proof_16Metric    int64
	Proof_128Metric   int64
	Proof_1024Metric  int64
	Cores             uint32
	Memory            []byte
	Storage           []byte
	Capabilities      []Capability
	MasterHeadFrame   uint64
	Bandwidth         uint64
	LastSeen          int64
}

type InMemoryPeerInfoManager struct {
	logger     *zap.Logger
	peerInfoCh chan *PeerManifest
	quitCh     chan struct{}
	peerInfoMx sync.RWMutex

	peerMap      map[string]*PeerManifest
	fastestPeers []*PeerManifest
}

var _ PeerInfoManager = (*InMemoryPeerInfoManager)(nil)

func NewInMemoryPeerInfoManager(logger *zap.Logger) *InMemoryPeerInfoManager {
	return &InMemoryPeerInfoManager{
		logger:       logger,
		peerInfoCh:   make(chan *PeerManifest),
		fastestPeers: []*PeerManifest{},
		peerMap:      make(map[string]*PeerManifest),
	}
}

func (m *InMemoryPeerInfoManager) Start() {
	go func() {
		for {
			select {
			case manifest := <-m.peerInfoCh:
				m.peerInfoMx.Lock()
				m.peerMap[string(manifest.PeerId)] = manifest
				m.searchAndInsertPeer(manifest)
				m.peerInfoMx.Unlock()
			case <-m.quitCh:
				return
			}
		}
	}()
}

func (m *InMemoryPeerInfoManager) Stop() {
	go func() {
		m.quitCh <- struct{}{}
	}()
}

func (m *InMemoryPeerInfoManager) AddPeerInfo(manifest *PeerManifest) {
	go func() {
		m.peerInfoCh <- manifest
	}()
}

func (m *InMemoryPeerInfoManager) GetPeerInfo(peerId []byte) *PeerManifest {
	m.peerInfoMx.RLock()
	manifest, ok := m.peerMap[string(peerId)]
	m.peerInfoMx.RUnlock()
	if !ok {
		return nil
	}
	return manifest
}

func (m *InMemoryPeerInfoManager) GetPeerMap() map[string]*PeerManifest {
	data := make(map[string]*PeerManifest)
	m.peerInfoMx.RLock()
	for k, v := range m.peerMap {
		data[k] = v
	}
	m.peerInfoMx.RUnlock()

	return data
}

func (m *InMemoryPeerInfoManager) GetPeersBySpeed() [][]byte {
	result := [][]byte{}
	m.peerInfoMx.RLock()
	for _, info := range m.fastestPeers {
		result = append(result, info.PeerId)
	}
	m.peerInfoMx.RUnlock()
	return result
}

// blatantly lifted from slices.BinarySearchFunc, optimized for direct insertion
// and uint64 comparison without overflow
func (m *InMemoryPeerInfoManager) searchAndInsertPeer(manifest *PeerManifest) {
	n := len(m.fastestPeers)
	i, j := 0, n
	for i < j {
		h := int(uint(i+j) >> 1)
		if m.fastestPeers[h].Bandwidth > manifest.Bandwidth {
			i = h + 1
		} else {
			j = h
		}
	}

	if i < n && m.fastestPeers[i].Bandwidth == manifest.Bandwidth &&
		bytes.Equal(m.fastestPeers[i].PeerId, manifest.PeerId) {
		m.fastestPeers[i] = manifest
	} else {
		m.fastestPeers = append(m.fastestPeers, new(PeerManifest))
		copy(m.fastestPeers[i+1:], m.fastestPeers[i:])
		m.fastestPeers[i] = manifest
	}
}
