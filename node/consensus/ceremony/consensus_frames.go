package ceremony

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/vdf"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func (e *CeremonyDataClockConsensusEngine) prove(
	previousFrame *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	if e.state == consensus.EngineStateProving {
		if !e.frameProverTrie.Contains(e.provingKeyAddress) {
			e.state = consensus.EngineStateCollecting
			return previousFrame, nil
		}
		e.logger.Info("proving new frame")

		commitments := [][]byte{}
		aggregations := []*protobufs.InclusionAggregateProof{}

		e.stagedKeyCommitsMx.Lock()
		if len(e.stagedKeyCommits) > 0 && len(e.stagedKeyPolynomials) > 0 {
			e.logger.Debug(
				"adding staged key commits to frame",
				zap.Uint64("frame_number", previousFrame.FrameNumber+1),
			)
			keyCommitments := []curves.PairingPoint{}
			keyInclusions := []*protobufs.InclusionCommitment{}
			keyPolynomials := [][]curves.PairingScalar{}
			i := uint32(0)

			for commit, inclusion := range e.stagedKeyCommits {
				e.logger.Debug(
					"adding staged key commit to aggregate proof",
					zap.Uint64("frame_number", previousFrame.FrameNumber+1),
					zap.Uint32("position", i),
				)
				keyCommitments = append(keyCommitments, commit)
				inclusion.FrameNumber = previousFrame.FrameNumber + 1
				inclusion.Position = i
				keyInclusions = append(keyInclusions, inclusion)
				keyPolynomials = append(keyPolynomials, e.stagedKeyPolynomials[commit])
			}

			proof, commitment, err := e.prover.ProveAggregate(
				keyPolynomials,
				keyCommitments,
			)
			if err != nil {
				e.logger.Error("could not produce proof", zap.Error(err))
				return nil, errors.Wrap(err, "prove")
			}
			if proof.IsIdentity() {
				return nil, errors.Wrap(errors.New("invalid proof"), "prove")
			}

			commitments = append(commitments, commitment.ToAffineCompressed())

			keyAggregation := &protobufs.InclusionAggregateProof{
				Filter:               e.filter,
				FrameNumber:          previousFrame.FrameNumber + 1,
				InclusionCommitments: keyInclusions,
				Proof:                proof.ToAffineCompressed(),
			}

			aggregations = append(aggregations, keyAggregation)

			e.stagedKeyCommits = make(
				map[curves.PairingPoint]*protobufs.InclusionCommitment,
			)
			e.stagedKeyPolynomials = make(
				map[curves.PairingPoint][]curves.PairingScalar,
			)
		}
		e.stagedKeyCommitsMx.Unlock()

		e.stagedLobbyStateTransitionsMx.Lock()
		executionOutput := &protobufs.IntrinsicExecutionOutput{}
		app, err := application.MaterializeApplicationFromFrame(previousFrame)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		if e.stagedLobbyStateTransitions == nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
		}

		app, err = app.ApplyTransition(
			previousFrame.FrameNumber,
			e.stagedLobbyStateTransitions,
		)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		lobbyState, err := app.MaterializeLobbyStateFromApplication()
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		executionOutput.Address = application.CEREMONY_ADDRESS
		executionOutput.Output, err = proto.Marshal(lobbyState)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		executionOutput.Proof, err = proto.Marshal(e.stagedLobbyStateTransitions)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		data, err := proto.Marshal(executionOutput)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		e.logger.Debug("encoded execution output")

		// Execution data in the ceremony is plaintext, we do not need to leverage
		// full encoding for commit/proof reference.
		digest := sha3.NewShake256()
		_, err = digest.Write(data)
		if err != nil {
			e.logger.Error(
				"error converting key bundle to polynomial",
				zap.Error(err),
			)
			return nil, errors.Wrap(err, "prove")
		}

		expand := make([]byte, 1024)
		_, err = digest.Read(expand)
		if err != nil {
			e.logger.Error(
				"error converting key bundle to polynomial",
				zap.Error(err),
			)
			return nil, errors.Wrap(err, "prove")
		}
		poly, err := e.prover.BytesToPolynomial(expand)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		e.logger.Debug("proving execution output for inclusion")
		polys, err := qcrypto.FFT(
			poly,
			*curves.BLS48581(
				curves.BLS48581G1().NewGeneratorPoint(),
			),
			16,
			false,
		)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		e.logger.Debug("converted execution output chunk to evaluation form")

		e.logger.Debug("creating kzg commitment")
		commitment, err := e.prover.Commit(polys)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}

		e.logger.Debug("creating kzg proof")
		proof, aggregate, err := e.prover.ProveAggregate(
			[][]curves.PairingScalar{polys},
			[]curves.PairingPoint{commitment},
		)
		if err != nil {
			e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
			e.stagedLobbyStateTransitionsMx.Unlock()
			return nil, errors.Wrap(err, "prove")
		}
		if proof.IsIdentity() {
			return nil, errors.Wrap(errors.New("invalid proof"), "prove")
		}

		commitments = append(commitments, aggregate.ToAffineCompressed())

		e.logger.Debug("finalizing execution proof")

		e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
		e.stagedLobbyStateTransitionsMx.Unlock()

		execInclusion := &protobufs.InclusionCommitment{
			Filter:      e.filter,
			FrameNumber: previousFrame.FrameNumber + 1,
			TypeUrl:     protobufs.IntrinsicExecutionOutputType,
			Data:        data,
			Commitment:  commitment.ToAffineCompressed(),
		}

		execAggregation := &protobufs.InclusionAggregateProof{
			Filter:      e.filter,
			FrameNumber: previousFrame.FrameNumber + 1,
			InclusionCommitments: []*protobufs.InclusionCommitment{
				execInclusion,
			},
			Proof: proof.ToAffineCompressed(),
		}

		aggregations = append(aggregations, execAggregation)

		frame, err := protobufs.ProveDataClockFrame(
			previousFrame,
			commitments,
			aggregations,
			e.provingKey,
			e.difficulty,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}
		e.state = consensus.EngineStatePublishing
		e.logger.Debug(
			"returning new proven frame",
			zap.Int("proof_count", len(aggregations)),
			zap.Int("commitment_count", len(commitments)),
		)
		return frame, nil
	}

	return nil, nil
}

func (e *CeremonyDataClockConsensusEngine) setFrame(
	frame *protobufs.ClockFrame,
) {
	pubkey := []byte{}
	discriminator := big.NewInt(0)
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if frame.PublicKeySignature == nil && frame.FrameNumber != 0 {
		e.logger.Error("could not set frame, signature invalid for non-zero frame")
		return
	} else if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
	}

	if len(pubkey) != 0 {
		var err error
		discriminator, err = poseidon.HashBytes(pubkey)
		if err != nil {
			e.logger.Error(
				"could not set frame",
				zap.Error(err),
			)
			return
		}
	}

	selector := new(big.Int).SetBytes(frame.ParentSelector)

	l := new(big.Int).Mod(new(big.Int).Sub(selector, discriminator), ff.Modulus())
	r := new(big.Int).Mod(new(big.Int).Sub(discriminator, selector), ff.Modulus())
	distance := r
	if l.Cmp(r) == -1 {
		distance = l
	}

	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Output[:516])

	parent, err := poseidon.HashBytes(previousSelectorBytes[:])
	if err != nil {
		panic(errors.Wrap(err, "set frame"))
	}
	e.logger.Debug("set frame", zap.Uint64("frame_number", frame.FrameNumber))
	e.currentDistance = distance
	e.frame = frame.FrameNumber
	e.parentSelector = parent.Bytes()
	e.activeFrame = frame
	go func() {
		e.frameChan <- frame
	}()
}

func (
	e *CeremonyDataClockConsensusEngine,
) createGenesisFrame() *protobufs.ClockFrame {
	e.logger.Info("creating genesis frame")
	for _, l := range strings.Split(string(e.input), "\n") {
		e.logger.Info(l)
	}

	b := sha3.Sum256(e.input)
	v := vdf.New(e.difficulty, b)

	v.Execute()
	o := v.GetOutput()
	inputMessage := o[:]

	e.logger.Info("encoding ceremony and phase one signatories")
	transcript := &protobufs.CeremonyTranscript{}
	for p, s := range qcrypto.CeremonyBLS48581G1 {
		transcript.G1Powers = append(
			transcript.G1Powers,
			&protobufs.BLS48581G1PublicKey{
				KeyValue: s.ToAffineCompressed(),
			},
		)
		e.logger.Info(fmt.Sprintf("encoded G1 power %d", p))
	}
	for p, s := range qcrypto.CeremonyBLS48581G2 {
		transcript.G2Powers = append(
			transcript.G2Powers,
			&protobufs.BLS48581G2PublicKey{
				KeyValue: s.ToAffineCompressed(),
			},
		)
		e.logger.Info(fmt.Sprintf("encoded G2 power %d", p))
	}

	transcript.RunningG1_256Witnesses = append(
		transcript.RunningG1_256Witnesses,
		&protobufs.BLS48581G1PublicKey{
			KeyValue: qcrypto.CeremonyRunningProducts[0].ToAffineCompressed(),
		},
	)

	transcript.RunningG2_256Powers = append(
		transcript.RunningG2_256Powers,
		&protobufs.BLS48581G2PublicKey{
			KeyValue: qcrypto.CeremonyPotPubKeys[len(qcrypto.CeremonyPotPubKeys)-1].
				ToAffineCompressed(),
		},
	)

	outputProof := &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{},
		TransitionInputs: [][]byte{},
	}

	proofBytes, err := proto.Marshal(outputProof)
	if err != nil {
		panic(err)
	}

	e.logger.Info("encoded transcript")
	e.logger.Info("encoding ceremony signatories into application state")

	rewardTrie := &tries.RewardCritbitTrie{}
	for _, s := range qcrypto.CeremonySignatories {
		pubkey := s.ToAffineCompressed()

		addr, err := poseidon.HashBytes(pubkey)
		if err != nil {
			panic(err)
		}

		addrBytes := addr.Bytes()
		addrBytes = append(make([]byte, 32-len(addrBytes)), addrBytes...)
		rewardTrie.Add(addrBytes, 0, 50)
	}

	trieBytes, err := rewardTrie.Serialize()
	if err != nil {
		panic(err)
	}

	ceremonyLobbyState := &protobufs.CeremonyLobbyState{
		LobbyState: 0,
		CeremonyState: &protobufs.CeremonyLobbyState_CeremonyOpenState{
			CeremonyOpenState: &protobufs.CeremonyOpenState{
				JoinedParticipants:    []*protobufs.CeremonyLobbyJoin{},
				PreferredParticipants: []*protobufs.Ed448PublicKey{},
			},
		},
		LatestTranscript: transcript,
		RewardTrie:       trieBytes,
	}
	outputBytes, err := proto.Marshal(ceremonyLobbyState)
	if err != nil {
		panic(err)
	}

	executionOutput := &protobufs.IntrinsicExecutionOutput{
		Address: []byte(e.filter),
		Output:  outputBytes,
		Proof:   proofBytes,
	}

	data, err := proto.Marshal(executionOutput)
	if err != nil {
		panic(err)
	}

	e.logger.Info("encoded execution output")

	digest := sha3.NewShake256()
	_, err = digest.Write(data)
	if err != nil {
		panic(err)
	}

	expand := make([]byte, 1024)
	_, err = digest.Read(expand)
	if err != nil {
		panic(err)
	}

	poly, err := e.prover.BytesToPolynomial(expand)
	if err != nil {
		panic(err)
	}

	e.logger.Info("proving execution output for inclusion")
	evalPoly, err := qcrypto.FFT(
		poly,
		*curves.BLS48581(
			curves.BLS48581G1().NewGeneratorPoint(),
		),
		16,
		false,
	)
	if err != nil {
		panic(err)
	}

	e.logger.Info(
		"converted execution output chunk to evaluation form",
		zap.Int("poly_size", len(evalPoly)),
	)

	e.logger.Info("creating kzg commitment")
	commitment, err := e.prover.Commit(evalPoly)
	if err != nil {
		panic(err)
	}

	e.logger.Info("creating kzg proof")
	proof, aggregate, err := e.prover.ProveAggregate(
		[][]curves.PairingScalar{evalPoly},
		[]curves.PairingPoint{commitment},
	)
	if err != nil {
		panic(err)
	}

	e.logger.Info("finalizing execution proof")

	inputMessage = append(
		append([]byte{}, inputMessage...),
		aggregate.ToAffineCompressed()...,
	)

	ceremonyExecutiveProof := &protobufs.InclusionAggregateProof{
		Filter:      e.filter,
		FrameNumber: 0,
		InclusionCommitments: []*protobufs.InclusionCommitment{
			{
				Filter:      e.filter,
				FrameNumber: 0,
				Position:    0,
				TypeUrl:     protobufs.IntrinsicExecutionOutputType,
				Data:        data,
				Commitment:  commitment.ToAffineCompressed(),
			},
		},
		Proof: proof.ToAffineCompressed(),
	}

	// Signatories are special, they don't have an inclusion proof because they
	// have not broadcasted communication keys, but they still get contribution
	// rights prior to PoMW, because they did produce meaningful work in the
	// first phase:
	e.logger.Info("encoding signatories to prover trie")

	for _, s := range qcrypto.CeremonySignatories {
		pubkey := s.ToAffineCompressed()
		e.logger.Info("0x" + hex.EncodeToString(pubkey))

		addr, err := poseidon.HashBytes(pubkey)
		if err != nil {
			panic(err)
		}

		addrBytes := addr.Bytes()
		addrBytes = append(make([]byte, 32-len(addrBytes)), addrBytes...)
		e.frameProverTrie.Add(addrBytes, 0)
	}

	e.logger.Info("proving genesis frame")
	input := []byte{}
	input = append(input, e.filter...)
	input = binary.BigEndian.AppendUint64(input, e.frame)
	input = binary.BigEndian.AppendUint64(input, uint64(0))
	input = binary.BigEndian.AppendUint32(input, e.difficulty)
	input = append(input, e.input...)

	b = sha3.Sum256(input)
	v = vdf.New(e.difficulty, b)

	v.Execute()
	o = v.GetOutput()

	frame := &protobufs.ClockFrame{
		Filter:         e.filter,
		FrameNumber:    e.frame,
		Timestamp:      0,
		Difficulty:     e.difficulty,
		Input:          inputMessage,
		Output:         o[:],
		ParentSelector: e.parentSelector,
		AggregateProofs: []*protobufs.InclusionAggregateProof{
			ceremonyExecutiveProof,
		},
		PublicKeySignature: nil,
	}

	parent, distance, selector, err := frame.GetParentSelectorAndDistance()
	if err != nil {
		panic(err)
	}

	txn, err := e.clockStore.NewTransaction()
	if err != nil {
		panic(err)
	}

	if err := e.clockStore.PutCandidateDataClockFrame(
		parent.Bytes(),
		distance.Bytes(),
		selector.Bytes(),
		frame,
		txn,
	); err != nil {
		panic(err)
	}

	if err := e.clockStore.PutDataClockFrame(
		frame,
		e.frameProverTrie,
		txn,
	); err != nil {
		panic(err)
	}

	if err := txn.Commit(); err != nil {
		panic(err)
	}

	e.setFrame(frame)
	return frame
}

func (e *CeremonyDataClockConsensusEngine) commitLongestPath() (
	*protobufs.ClockFrame,
	error,
) {
	current, err := e.clockStore.GetLatestDataClockFrame(e.filter, nil)
	if err != nil {
		return nil, errors.Wrap(err, "commit longest path")
	}

	e.logger.Info(
		"searching from committed frame",
		zap.Uint64("frame_number", current.FrameNumber),
	)

	runningFrames := [][]*protobufs.ClockFrame{{current}}
	commitReady := false
	currentDepth := 0

	for {
		nextRunningFrames := [][]*protobufs.ClockFrame{}
		for _, s := range runningFrames {
			e.logger.Info(
				"ranging over candidates for frame",
				zap.Uint64("frame_number", s[currentDepth].FrameNumber),
			)
			selector, err := s[currentDepth].GetSelector()
			if err != nil {
				return nil, errors.Wrap(err, "commit longest path")
			}

			iter, err := e.clockStore.RangeCandidateDataClockFrames(
				e.filter,
				selector.Bytes(),
				s[currentDepth].FrameNumber+1,
			)
			if err != nil {
				return nil, errors.Wrap(err, "commit longest path")
			}

			for iter.First(); iter.Valid(); iter.Next() {
				value, err := iter.Value()
				if err != nil {
					return nil, errors.Wrap(err, "commit longest path")
				}

				selectorBytes := selector.Bytes()
				selectorBytes = append(
					make([]byte, 32-len(selectorBytes)),
					selectorBytes...,
				)
				nearest := e.frameProverTrie.FindNearest(
					selectorBytes,
				)
				addr, err := value.GetAddress()

				// If we got the outright nearest, then skip all this, we know this is
				// the right frame for the selector.
				if err != nil && bytes.Equal(nearest.Bits(), addr) {
					nextRunningFrames = append(
						nextRunningFrames,
						append(
							append([]*protobufs.ClockFrame{}, s...),
							value,
						),
					)
					break
				}

				// Iterated values will always be in order of shortest distance, this
				// will always keep closest selected, longest path
				if current.FrameNumber < value.FrameNumber {
					e.logger.Info(
						"setting longest path cursor to frame",
						zap.Uint64("frame_number", value.FrameNumber),
					)
					current = value
				}

				e.logger.Info(
					"adding candidate",
					zap.Uint64("frame_number", value.FrameNumber),
				)

				nextRunningFrames = append(
					nextRunningFrames,
					append(
						append([]*protobufs.ClockFrame{}, s...),
						value,
					),
				)
			}

			iter.Close()
		}

		if commitReady && len(nextRunningFrames) == 1 {
			commitReady = false
			e.logger.Info(
				"consensus found, committing frames",
				zap.Int("commit_depth", len(runningFrames[0])),
			)

			txn, err := e.clockStore.NewTransaction()
			if err != nil {
				return nil, errors.Wrap(err, "commit longest path")
			}

			for _, s := range runningFrames[0][1:] {
				e.logger.Info(
					"committing candidate",
					zap.Uint64("frame_number", s.FrameNumber),
					zap.Binary("prover", s.GetPublicKeySignatureEd448().PublicKey.KeyValue),
				)

				addr, err := s.GetAddress()
				if err != nil {
					return nil, errors.Wrap(err, "commit longest path")
				}

				e.frameProverTrie.Add(addr, s.FrameNumber)
				if err := e.clockStore.PutDataClockFrame(
					s,
					e.frameProverTrie,
					txn,
				); err != nil {
					e.logger.Error(
						"could not commit candidate",
						zap.Error(err),
						zap.Uint64("frame_number", s.FrameNumber),
						zap.Binary("output", s.Output),
					)
					return nil, errors.Wrap(err, "commit longest path")
				}

				e.logger.Debug(
					"committing aggregate proofs",
					zap.Int("proof_count", len(s.AggregateProofs)),
				)

				for _, p := range s.AggregateProofs {
					e.logger.Debug(
						"committing inclusions",
						zap.Int("inclusions_count", len(p.InclusionCommitments)),
					)

					for _, c := range p.InclusionCommitments {
						switch c.TypeUrl {
						case protobufs.ProvingKeyAnnouncementType:
							provingKey := &protobufs.ProvingKeyAnnouncement{}
							if err := proto.Unmarshal(c.Data, provingKey); err != nil {
								e.logger.Error(
									"could not commit candidate",
									zap.Error(err),
									zap.Uint64("frame_number", s.FrameNumber),
									zap.Binary("commitment", c.Commitment),
								)
								return nil, errors.Wrap(err, "commit longest path")
							}

							e.logger.Debug(
								"committing proving key",
								zap.Uint64("frame_number", s.FrameNumber),
								zap.Binary("commitment", c.Commitment),
							)

							if err := e.keyStore.IncludeProvingKey(c, txn); err != nil {
								e.logger.Error(
									"could not commit candidate",
									zap.Error(err),
									zap.Uint64("frame_number", s.FrameNumber),
									zap.Binary("output", s.Output),
								)
								return nil, errors.Wrap(err, "commit longest path")
							}
						case protobufs.KeyBundleAnnouncementType:
							bundle := &protobufs.KeyBundleAnnouncement{}
							if err := proto.Unmarshal(c.Data, bundle); err != nil {
								e.logger.Error(
									"could not commit candidate",
									zap.Error(err),
									zap.Uint64("frame_number", s.FrameNumber),
									zap.Binary("commitment", c.Commitment),
								)
								return nil, errors.Wrap(err, "commit longest path")
							}

							e.logger.Debug(
								"committing key bundle",
								zap.Uint64("frame_number", s.FrameNumber),
								zap.Binary("commitment", c.Commitment),
							)

							if err := e.keyStore.PutKeyBundle(
								bundle.ProvingKeyBytes,
								c,
								txn,
							); err != nil {
								e.logger.Error(
									"could not commit candidate",
									zap.Error(err),
									zap.Uint64("frame_number", s.FrameNumber),
									zap.Binary("output", s.Output),
								)
								return nil, errors.Wrap(err, "commit longest path")
							}
						}
					}
				}
			}

			if err := txn.Commit(); err != nil {
				e.logger.Error(
					"could not commit candidates",
					zap.Error(err),
				)
				return nil, errors.Wrap(err, "commit longest path")
			}

			runningFrames = [][]*protobufs.ClockFrame{
				{nextRunningFrames[0][currentDepth+1]},
			}
			currentDepth = 0
		} else {
			e.logger.Info(
				"not ready to commit",
				zap.Int("forks", len(nextRunningFrames)),
				zap.Int("current_depth", currentDepth),
			)
			commitReady = len(nextRunningFrames) == 1
			runningFrames = nextRunningFrames
			currentDepth++
		}

		if len(nextRunningFrames) == 0 {
			e.logger.Info("deepest consensus reached")
			break
		}
	}

	return current, nil
}

func (e *CeremonyDataClockConsensusEngine) collect(
	currentFramePublished *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	if e.state == consensus.EngineStateCollecting {
		e.logger.Info("collecting vdf proofs")

		latest, err := e.clockStore.GetLatestDataClockFrame(e.filter, nil)
		if err != nil {
			e.logger.Error("could not obtain latest clock frame", zap.Error(err))

			return nil, errors.Wrap(err, "collect")
		}

		if e.syncingStatus == SyncStatusNotSyncing {
			peerId, err := e.pubSub.GetRandomPeer(e.filter)
			if err != nil {
				if errors.Is(err, p2p.ErrNoPeersAvailable) {
					e.logger.Warn("no peers available, skipping sync")
				} else {
					e.logger.Error("error while fetching random peer", zap.Error(err))
				}
			} else {
				e.syncingStatus = SyncStatusAwaitingResponse
				e.logger.Info(
					"setting syncing target",
					zap.String("peer_id", peer.ID(peerId).String()),
				)
				channel := e.createPeerReceiveChannel(peerId)
				e.pubSub.Subscribe(channel, e.handleSync, true)
				e.syncingTarget = peerId

				e.pubSub.Subscribe(
					append(append([]byte{}, e.filter...), peerId...),
					func(message *pb.Message) error { return nil },
					true,
				)

				go func() {
					time.Sleep(2 * time.Second)
					if err := e.publishMessage(
						append(append([]byte{}, e.filter...), peerId...),
						&protobufs.ClockFramesRequest{
							Filter:          e.filter,
							FromFrameNumber: latest.FrameNumber + 1,
						}); err != nil {
						e.logger.Error(
							"could not publish clock frame request",
							zap.Error(err),
						)
					}
				}()
			}
		}

		waitDecay := time.Duration(2000)
		for e.syncingStatus != SyncStatusNotSyncing {
			e.logger.Info(
				"waiting for sync to complete...",
				zap.Duration("wait_decay", waitDecay),
			)

			time.Sleep(waitDecay * time.Millisecond)

			waitDecay = waitDecay * 2
			if waitDecay >= (100 * (2 << 6)) {
				if e.syncingStatus == SyncStatusAwaitingResponse {
					e.logger.Info("maximum wait for sync response, skipping sync")
					e.syncingStatus = SyncStatusNotSyncing
					break
				} else {
					waitDecay = 100 * (2 << 6)
				}
			}
		}

		e.logger.Info("selecting leader")
		latestFrame, err := e.commitLongestPath()
		if err != nil {
			e.logger.Error("could not collect longest path", zap.Error(err))
			return nil, errors.Wrap(err, "collect")
		}

		go func() {
			_, err = e.keyStore.GetProvingKey(e.provingKeyBytes)
			if errors.Is(err, store.ErrNotFound) &&
				latestFrame.FrameNumber-e.lastKeyBundleAnnouncementFrame > 6 {
				if err = e.announceKeyBundle(); err != nil {
					panic(err)
				}
				e.lastKeyBundleAnnouncementFrame = latestFrame.FrameNumber
			}
		}()

		e.logger.Info(
			"returning leader frame",
			zap.Uint64("frame_number", latestFrame.FrameNumber),
		)

		if latestFrame.FrameNumber >= currentFramePublished.FrameNumber {
			e.setFrame(latestFrame)
			e.state = consensus.EngineStateProving
			return latestFrame, nil
		} else {
			return latestFrame, nil
		}
	}

	return nil, nil
}
