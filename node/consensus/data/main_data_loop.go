package data

import (
	"bytes"
	"slices"
	"time"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func (
	e *DataClockConsensusEngine,
) GetFrameProverTries() []*tries.RollingFrecencyCritbitTrie {
	e.frameProverTriesMx.RLock()
	frameProverTries := make(
		[]*tries.RollingFrecencyCritbitTrie,
		len(e.frameProverTries),
	)

	for i, trie := range e.frameProverTries {
		newTrie := &tries.RollingFrecencyCritbitTrie{}
		b, err := trie.Serialize()
		if err != nil {
			panic(err)
		}

		err = newTrie.Deserialize(b)
		if err != nil {
			panic(err)
		}
		frameProverTries[i] = newTrie
	}

	e.frameProverTriesMx.RUnlock()
	return frameProverTries
}

func (e *DataClockConsensusEngine) runLoop() {
	dataFrameCh := e.dataTimeReel.NewFrameCh()

	for e.state < consensus.EngineStateStopping {
		peerCount := e.pubSub.GetNetworkPeersCount()
		if peerCount < e.minimumPeersRequired {
			e.logger.Info(
				"waiting for minimum peers",
				zap.Int("peer_count", peerCount),
			)
			time.Sleep(1 * time.Second)
		} else {
			latestFrame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			select {
			case dataFrame := <-dataFrameCh:
				if latestFrame, err = e.collect(dataFrame); err != nil {
					e.logger.Error("could not collect", zap.Error(err))
				}

				dataFrame, err := e.dataTimeReel.Head()
				if err != nil {
					panic(err)
				}

				if latestFrame != nil &&
					dataFrame.FrameNumber > latestFrame.FrameNumber {
					latestFrame = dataFrame
				}

				if e.latestFrameReceived < latestFrame.FrameNumber {
					e.latestFrameReceived = latestFrame.FrameNumber
				}

				trie := e.GetFrameProverTries()[0]
				selBI, _ := dataFrame.GetSelector()
				sel := make([]byte, 32)
				sel = selBI.FillBytes(sel)

				if bytes.Equal(
					trie.FindNearest(sel).External.Key,
					e.provingKeyAddress,
				) {
					var nextFrame *protobufs.ClockFrame
					if nextFrame, err = e.prove(latestFrame); err != nil {
						e.logger.Error("could not prove", zap.Error(err))
						e.state = consensus.EngineStateCollecting
						continue
					}

					e.proverTrieRequestsMx.Lock()
					joinAddrs := tries.NewMinHeap[peerSeniorityItem]()
					leaveAddrs := tries.NewMinHeap[peerSeniorityItem]()
					for _, addr := range e.proverTrieJoinRequests {
						if _, ok := (*e.peerSeniority)[addr]; !ok {
							joinAddrs.Push(peerSeniorityItem{
								addr:      addr,
								seniority: 0,
							})
						} else {
							joinAddrs.Push((*e.peerSeniority)[addr])
						}
					}
					for _, addr := range e.proverTrieLeaveRequests {
						if _, ok := (*e.peerSeniority)[addr]; !ok {
							leaveAddrs.Push(peerSeniorityItem{
								addr:      addr,
								seniority: 0,
							})
						} else {
							leaveAddrs.Push((*e.peerSeniority)[addr])
						}
					}
					for _, addr := range e.proverTrieResumeRequests {
						if _, ok := e.proverTriePauseRequests[addr]; ok {
							delete(e.proverTriePauseRequests, addr)
						}
					}

					joinReqs := make([]peerSeniorityItem, len(joinAddrs.All()))
					copy(joinReqs, joinAddrs.All())
					slices.Reverse(joinReqs)
					leaveReqs := make([]peerSeniorityItem, len(leaveAddrs.All()))
					copy(leaveReqs, leaveAddrs.All())
					slices.Reverse(leaveReqs)

					e.proverTrieJoinRequests = make(map[string]string)
					e.proverTrieLeaveRequests = make(map[string]string)
					e.proverTrieRequestsMx.Unlock()

					e.frameProverTriesMx.Lock()
					for _, addr := range joinReqs {
						rings := len(e.frameProverTries)
						last := e.frameProverTries[rings-1]
						set := last.FindNearestAndApproximateNeighbors(make([]byte, 32))
						if len(set) == 1024 {
							e.frameProverTries = append(
								e.frameProverTries,
								&tries.RollingFrecencyCritbitTrie{},
							)
							last = e.frameProverTries[rings]
						}
						last.Add([]byte(addr.addr), nextFrame.FrameNumber)
					}
					for _, addr := range leaveReqs {
						for _, t := range e.frameProverTries {
							if bytes.Equal(
								t.FindNearest([]byte(addr.addr)).External.Key,
								[]byte(addr.addr),
							) {
								t.Remove([]byte(addr.addr))
								break
							}
						}
					}
					e.frameProverTriesMx.Unlock()

					e.dataTimeReel.Insert(nextFrame, false)

					if err = e.publishProof(nextFrame); err != nil {
						e.logger.Error("could not publish", zap.Error(err))
						e.state = consensus.EngineStateCollecting
					}
					break
				}
			case <-time.After(20 * time.Second):
				dataFrame, err := e.dataTimeReel.Head()
				if err != nil {
					panic(err)
				}

				if latestFrame, err = e.collect(dataFrame); err != nil {
					e.logger.Error("could not collect", zap.Error(err))
					continue
				}

				if latestFrame == nil ||
					latestFrame.FrameNumber < dataFrame.FrameNumber {
					latestFrame, err = e.dataTimeReel.Head()
					if err != nil {
						panic(err)
					}
				}

				if e.latestFrameReceived < latestFrame.FrameNumber {
					e.latestFrameReceived = latestFrame.FrameNumber
				}

				for _, trie := range e.GetFrameProverTries() {
					if bytes.Equal(
						trie.FindNearest(e.provingKeyAddress).External.Key,
						e.provingKeyAddress,
					) {
						var nextFrame *protobufs.ClockFrame
						if nextFrame, err = e.prove(latestFrame); err != nil {
							e.logger.Error("could not prove", zap.Error(err))
							e.state = consensus.EngineStateCollecting
							continue
						}

						e.proverTrieRequestsMx.Lock()
						joinAddrs := tries.NewMinHeap[peerSeniorityItem]()
						leaveAddrs := tries.NewMinHeap[peerSeniorityItem]()
						for _, addr := range e.proverTrieJoinRequests {
							if _, ok := (*e.peerSeniority)[addr]; !ok {
								joinAddrs.Push(peerSeniorityItem{
									addr:      addr,
									seniority: 0,
								})
							} else {
								joinAddrs.Push((*e.peerSeniority)[addr])
							}
						}
						for _, addr := range e.proverTrieLeaveRequests {
							if _, ok := (*e.peerSeniority)[addr]; !ok {
								leaveAddrs.Push(peerSeniorityItem{
									addr:      addr,
									seniority: 0,
								})
							} else {
								leaveAddrs.Push((*e.peerSeniority)[addr])
							}
						}
						for _, addr := range e.proverTrieResumeRequests {
							if _, ok := e.proverTriePauseRequests[addr]; ok {
								delete(e.proverTriePauseRequests, addr)
							}
						}

						joinReqs := make([]peerSeniorityItem, len(joinAddrs.All()))
						copy(joinReqs, joinAddrs.All())
						slices.Reverse(joinReqs)
						leaveReqs := make([]peerSeniorityItem, len(leaveAddrs.All()))
						copy(leaveReqs, leaveAddrs.All())
						slices.Reverse(leaveReqs)

						e.proverTrieJoinRequests = make(map[string]string)
						e.proverTrieLeaveRequests = make(map[string]string)
						e.proverTrieRequestsMx.Unlock()

						e.frameProverTriesMx.Lock()
						for _, addr := range joinReqs {
							rings := len(e.frameProverTries)
							last := e.frameProverTries[rings-1]
							set := last.FindNearestAndApproximateNeighbors(make([]byte, 32))
							if len(set) == 8 {
								e.frameProverTries = append(
									e.frameProverTries,
									&tries.RollingFrecencyCritbitTrie{},
								)
								last = e.frameProverTries[rings]
							}
							last.Add([]byte(addr.addr), nextFrame.FrameNumber)
						}
						for _, addr := range leaveReqs {
							for _, t := range e.frameProverTries {
								if bytes.Equal(
									t.FindNearest([]byte(addr.addr)).External.Key,
									[]byte(addr.addr),
								) {
									t.Remove([]byte(addr.addr))
									break
								}
							}
						}
						e.frameProverTriesMx.Unlock()

						e.dataTimeReel.Insert(nextFrame, false)

						if err = e.publishProof(nextFrame); err != nil {
							e.logger.Error("could not publish", zap.Error(err))
							e.state = consensus.EngineStateCollecting
						}
						break
					}
				}
			}
		}
	}
}
