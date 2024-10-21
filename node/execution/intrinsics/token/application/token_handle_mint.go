package application

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleMint(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.MintCoinRequest,
) ([]*protobufs.TokenOutput, error) {
	if t == nil || t.Proofs == nil {
		return nil, ErrInvalidStateTransition
	}

	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
	}
	if err := t.Signature.Verify(payload); err != nil {
		return nil, ErrInvalidStateTransition
	}
	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	addr, err := poseidon.HashBytes(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	if _, touched := lockMap[string(t.Signature.PublicKey.KeyValue)]; touched {
		return nil, ErrInvalidStateTransition
	}

	if len(t.Proofs) >= 3 &&
		len(t.Proofs) < 14 &&
		bytes.Equal(
			t.Proofs[0],
			[]byte("pre-dusk"),
		) && (!bytes.Equal(t.Proofs[1], make([]byte, 32)) ||
		currentFrameNumber < 60480) {
		deletes := []*protobufs.TokenOutput{}
		outputs := []*protobufs.TokenOutput{}
		if !bytes.Equal(t.Proofs[1], make([]byte, 32)) {
			pre, err := a.CoinStore.GetPreCoinProofByAddress(t.Proofs[1])
			if err != nil {
				return nil, ErrInvalidStateTransition
			}
			if !bytes.Equal(
				pre.Owner.GetImplicitAccount().Address,
				addr.FillBytes(make([]byte, 32)),
			) && !bytes.Equal(
				pre.Owner.GetImplicitAccount().Address,
				altAddr.FillBytes(make([]byte, 32)),
			) {
				return nil, ErrInvalidStateTransition
			}

			deletes = append(deletes, &protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_DeletedProof{
					DeletedProof: pre,
				},
			})
		}

		var previousIncrement = uint32(0xFFFFFFFF)
		reward := new(big.Int)
		var index uint32
		var indexProof []byte
		var parallelism uint32
		var kzgCommitment []byte
		var kzgProof []byte
		for pi, data := range t.Proofs[2:] {
			if len(data) < 28 {
				return nil, ErrInvalidStateTransition
			}

			increment := binary.BigEndian.Uint32(data[:4])
			parallelism = binary.BigEndian.Uint32(data[4:8])
			inputLen := binary.BigEndian.Uint64(data[8:16])

			if len(deletes) != 0 && pi == 0 {
				if deletes[0].GetDeletedProof().Difficulty-1 != increment {
					return nil, ErrInvalidStateTransition
				}
			} else if pi == 0 && bytes.Equal(t.Proofs[1], make([]byte, 32)) {
				frames, _, err := a.CoinStore.GetPreCoinProofsForOwner(
					addr.FillBytes(make([]byte, 32)),
				)
				if err != nil || len(frames) != 0 {
					return nil, ErrInvalidStateTransition
				}
			} else if pi != 0 {
				if increment != previousIncrement-1 {
					return nil, ErrInvalidStateTransition
				}
			}
			previousIncrement = increment

			if uint64(len(data[16:])) < inputLen+8 {
				return nil, ErrInvalidStateTransition
			}

			input := make([]byte, inputLen)
			copy(input[:], data[16:16+inputLen])

			outputLen := binary.BigEndian.Uint64(data[16+inputLen : 16+inputLen+8])

			if uint64(len(data[16+inputLen+8:])) < outputLen {
				return nil, ErrInvalidStateTransition
			}

			output := make([]byte, outputLen)
			copy(output[:], data[16+inputLen+8:])
			dataProver := crypto.NewKZGInclusionProver(a.Logger)
			wesoProver := crypto.NewWesolowskiFrameProver(a.Logger)
			index = binary.BigEndian.Uint32(output[:4])
			indexProof = output[4:520]
			kzgCommitment = output[520:594]
			kzgProof = output[594:668]
			ip := sha3.Sum512(indexProof)

			v, err := dataProver.VerifyRaw(
				ip[:],
				kzgCommitment,
				int(index),
				kzgProof,
				nearestApplicablePowerOfTwo(uint64(parallelism)),
			)
			if err != nil {
				return nil, ErrInvalidStateTransition
			}

			if !v {
				return nil, ErrInvalidStateTransition
			}

			wp := []byte{}
			wp = append(wp, peerId...)
			wp = append(wp, input...)
			v = wesoProver.VerifyPreDuskChallengeProof(
				wp,
				increment,
				index,
				indexProof,
			)
			if !v {
				return nil, ErrInvalidStateTransition
			}

			pomwBasis := big.NewInt(1200000)
			additional := new(big.Int).Mul(pomwBasis, big.NewInt(int64(parallelism)))
			reward.Add(
				reward,
				additional,
			)
		}

		if len(deletes) != 0 {
			reward.Add(
				reward,
				new(big.Int).SetBytes(deletes[0].GetDeletedProof().Amount),
			)
		}

		if previousIncrement == uint32(0xffffffff) {
			return nil, ErrInvalidStateTransition
		}

		if previousIncrement != 0 {
			add := &protobufs.PreCoinProof{
				Amount:      reward.FillBytes(make([]byte, 32)),
				Index:       index,
				IndexProof:  indexProof,
				Commitment:  kzgCommitment,
				Proof:       append(append([]byte{}, kzgProof...), indexProof...),
				Parallelism: parallelism,
				Difficulty:  previousIncrement,
				Owner: &protobufs.AccountRef{
					Account: &protobufs.AccountRef_ImplicitAccount{
						ImplicitAccount: &protobufs.ImplicitAccount{
							ImplicitType: 0,
							Address:      addr.FillBytes(make([]byte, 32)),
						},
					},
				},
			}
			outputs = append(outputs, &protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Proof{
					Proof: add,
				},
			})
		} else {
			add := &protobufs.Coin{
				Amount:       reward.FillBytes(make([]byte, 32)),
				Intersection: make([]byte, 1024),
				Owner: &protobufs.AccountRef{
					Account: &protobufs.AccountRef_ImplicitAccount{
						ImplicitAccount: &protobufs.ImplicitAccount{
							ImplicitType: 0,
							Address:      addr.FillBytes(make([]byte, 32)),
						},
					},
				},
			}
			outputs = append(outputs, &protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: add,
				},
			})
		}
		outputs = append(outputs, deletes...)
		lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
		return outputs, nil
	} else {
		ring := -1
		addrBytes := addr.FillBytes(make([]byte, 32))
		for i, t := range a.Tries {
			n := t.FindNearest(addrBytes)
			if n != nil && bytes.Equal(n.External.Key, addrBytes) {
				ring = i
			}
		}
		if ring == -1 {
			return nil, ErrInvalidStateTransition
		}
		outputs := []*protobufs.TokenOutput{}
		for _, p := range t.Proofs {
			if len(p) < 516+len(peerId)+8+32 {
				return nil, ErrInvalidStateTransition
			}

			if !bytes.Equal(p[516:len(peerId)], []byte(peerId)) {
				return nil, ErrInvalidStateTransition
			}

			wesoProver := crypto.NewWesolowskiFrameProver(a.Logger)

			frameNumber := binary.BigEndian.Uint64(
				p[516+len(peerId) : 516+len(peerId)+8],
			)
			if frameNumber > currentFrameNumber {
				return nil, ErrInvalidStateTransition
			}

			frames, proofs, err := a.CoinStore.GetPreCoinProofsForOwner(
				addr.FillBytes(make([]byte, 32)),
			)
			if err == nil {
				none := true
				for _, f := range frames {
					if f == frameNumber {
						none = false
						break
					}
				}

				if !none {
					for _, pr := range proofs {
						if bytes.Equal(pr.Proof, p) {
							return nil, ErrInvalidStateTransition
						}
					}
				}
			}

			if !wesoProver.VerifyChallengeProof(p[516:], a.Difficulty, p[:516]) {
				return nil, ErrInvalidStateTransition
			}

			scale := len(p2p.GetOnesIndices(p[516+len(peerId)+8 : 32]))
			if scale == 0 {
				return nil, ErrInvalidStateTransition
			}

			ringFactor := big.NewInt(2)
			ringFactor.Exp(ringFactor, big.NewInt(int64(ring)), nil)
			storage := big.NewInt(int64(1024 / (256 / scale)))
			unitFactor := big.NewInt(8000000000)
			storage.Mul(storage, unitFactor)
			storage.Quo(storage, ringFactor)

			outputs = append(
				outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Proof{
						Proof: &protobufs.PreCoinProof{
							Amount:     storage.FillBytes(make([]byte, 32)),
							Proof:      p,
							Difficulty: a.Difficulty,
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      addr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				},
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Coin{
						Coin: &protobufs.Coin{
							Amount:       storage.FillBytes(make([]byte, 32)),
							Intersection: make([]byte, 1024),
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      addr.FillBytes(make([]byte, 32)),
									},
								},
							},
						},
					},
				},
			)
		}
		lockMap[string(t.Signature.PublicKey.KeyValue)] = struct{}{}
		return outputs, nil
	}
}
