package application

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

var ErrInvalidStateTransition = errors.New("invalid state transition")

var TOKEN_ADDRESS = []byte{
	// poseidon("q_mainnet_token")
	0x11, 0x55, 0x85, 0x84, 0xaf, 0x70, 0x17, 0xa9,
	0xbf, 0xd1, 0xff, 0x18, 0x64, 0x30, 0x2d, 0x64,
	0x3f, 0xbe, 0x58, 0xc6, 0x2d, 0xcf, 0x90, 0xcb,
	0xcd, 0x8f, 0xde, 0x74, 0xa2, 0x67, 0x94, 0xd9,
}

type TokenApplication struct {
	TokenOutputs *protobufs.TokenOutputs
	Tries        []*tries.RollingFrecencyCritbitTrie
	CoinStore    store.CoinStore
	Logger       *zap.Logger
	Difficulty   uint32
}

func GetOutputsFromClockFrame(
	frame *protobufs.ClockFrame,
) (
	*protobufs.TokenRequests,
	*protobufs.TokenOutputs,
	error,
) {
	var associatedProof []byte
	var tokenOutputs *protobufs.TokenOutputs
	if len(frame.AggregateProofs) > 0 {
		for _, proofs := range frame.AggregateProofs {
			for _, inclusion := range proofs.InclusionCommitments {
				if inclusion.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					output := protobufs.IntrinsicExecutionOutput{}
					if err := proto.Unmarshal(inclusion.Data, &output); err != nil {
						return nil, nil, errors.Wrap(err, "get outputs from clock frame")
					}

					tokenOutputs = &protobufs.TokenOutputs{}
					if err := proto.Unmarshal(output.Output, tokenOutputs); err != nil {
						return nil, nil, errors.Wrap(err, "get outputs from clock frame")
					}

					associatedProof = output.Proof
				}
			}
		}
	}

	transition := &protobufs.TokenRequests{}
	if err := proto.Unmarshal(associatedProof, transition); err != nil {
		return nil, nil, errors.Wrap(err, "get outputs from clock frame")
	}

	return transition, tokenOutputs, nil
}

func MaterializeApplicationFromFrame(
	frame *protobufs.ClockFrame,
	tries []*tries.RollingFrecencyCritbitTrie,
	store store.CoinStore,
	logger *zap.Logger,
) (*TokenApplication, error) {
	_, tokenOutputs, err := GetOutputsFromClockFrame(frame)
	if err != nil {
		return nil, errors.Wrap(err, "materialize application from frame")
	}

	return &TokenApplication{
		TokenOutputs: tokenOutputs,
		Tries:        tries,
		CoinStore:    store,
		Logger:       logger,
		Difficulty:   frame.Difficulty,
	}, nil
}

func (a *TokenApplication) ApplyTransitions(
	currentFrameNumber uint64,
	transitions *protobufs.TokenRequests,
	skipFailures bool,
) (
	*TokenApplication,
	*protobufs.TokenRequests,
	*protobufs.TokenRequests,
	error,
) {
	finalizedTransitions := &protobufs.TokenRequests{}
	failedTransitions := &protobufs.TokenRequests{}
	outputs := &protobufs.TokenOutputs{}

	for _, transition := range transitions.Requests {
	req:
		switch t := transition.Request.(type) {
		case *protobufs.TokenRequest_Announce:
			var primary *protobufs.Ed448Signature
			payload := []byte{}
			for i, p := range t.Announce.PublicKeySignaturesEd448 {
				if i == 0 {
					primary = p
				} else {
					payload = append(payload, p.PublicKey.KeyValue...)
					if err := p.Verify(primary.PublicKey.KeyValue); err != nil {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								err,
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
					}
				}
			}
			if primary == nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						ErrInvalidStateTransition,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}
			if err := primary.Verify(payload); err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			payload = []byte("mint")
			for _, p := range t.Announce.InitialProof.Proofs {
				payload = append(payload, p...)
			}
			if err := t.Announce.InitialProof.Signature.Verify(payload); err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}
			pk, err := pcrypto.UnmarshalEd448PublicKey(
				t.Announce.InitialProof.Signature.PublicKey.KeyValue,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			peerId, err := peer.IDFromPublicKey(pk)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			addr, err := poseidon.HashBytes(
				t.Announce.InitialProof.Signature.PublicKey.KeyValue,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			if len(t.Announce.InitialProof.Proofs) == 3 &&
				bytes.Equal(
					t.Announce.InitialProof.Proofs[0],
					[]byte("pre-dusk"),
				) && bytes.Equal(t.Announce.InitialProof.Proofs[1], make([]byte, 32)) &&
				currentFrameNumber < 604800 {
				delete := []*protobufs.TokenOutput{}
				if !bytes.Equal(t.Announce.InitialProof.Proofs[1], make([]byte, 32)) {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				data := t.Announce.InitialProof.Proofs[3]
				if len(data) < 28 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				increment := binary.BigEndian.Uint32(data[:4])
				parallelism := binary.BigEndian.Uint32(data[8:12])
				inputLen := binary.BigEndian.Uint64(data[12:20])

				if len(delete) != 0 {
					if delete[0].GetDeletedProof().Difficulty-1 != increment {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								errors.New("invalid data"),
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
					}
				}

				if uint64(len(data[20:])) < inputLen+8 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				input := make([]byte, inputLen)
				copy(input[:], data[20:20+inputLen])

				outputLen := binary.BigEndian.Uint64(data[20+inputLen : 20+inputLen+8])

				if uint64(len(data[20+inputLen+8:])) < outputLen {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				output := make([]byte, outputLen)
				copy(output[:], data[20+inputLen+8:])
				dataProver := crypto.NewKZGInclusionProver(a.Logger)
				wesoProver := crypto.NewWesolowskiFrameProver(a.Logger)
				index := binary.BigEndian.Uint32(output[:4])
				indexProof := output[4:520]
				kzgCommitment := output[520:594]
				kzgProof := output[594:668]
				ip := sha3.Sum512(indexProof)

				v, err := dataProver.VerifyRaw(
					ip[:],
					kzgCommitment,
					int(index),
					kzgProof,
					nearestPowerOfTwo(uint64(parallelism)),
				)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				if !v {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
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
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				pomwBasis := big.NewInt(1200000)

				reward := new(big.Int).Mul(pomwBasis, big.NewInt(int64(parallelism)))
				if len(delete) != 0 {
					reward.Add(
						reward,
						new(big.Int).SetBytes(delete[0].GetDeletedProof().Amount),
					)
				}

				if increment != 0 {
					add := &protobufs.PreCoinProof{
						Amount:      reward.FillBytes(make([]byte, 32)),
						Index:       index,
						IndexProof:  indexProof,
						Commitment:  kzgCommitment,
						Proof:       append(append([]byte{}, kzgProof...), indexProof...),
						Parallelism: parallelism,
						Difficulty:  increment,
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      addr.FillBytes(make([]byte, 32)),
								},
							},
						},
					}
					outputs.Outputs = append(outputs.Outputs, &protobufs.TokenOutput{
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
					outputs.Outputs = append(outputs.Outputs, &protobufs.TokenOutput{
						Output: &protobufs.TokenOutput_Coin{
							Coin: add,
						},
					})
				}
				outputs.Outputs = append(outputs.Outputs, delete...)
			} else {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}
		case *protobufs.TokenRequest_Merge:
			newCoin := &protobufs.Coin{}
			newTotal := new(big.Int)
			newIntersection := make([]byte, 1024)
			payload := []byte("merge")
			for _, c := range t.Merge.Coins {
				payload = append(payload, c.Address...)
			}
			if err := t.Merge.Signature.Verify(payload); err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			addr, err := poseidon.HashBytes(t.Merge.Signature.PublicKey.KeyValue)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}
			pk, err := pcrypto.UnmarshalEd448PublicKey(
				t.Merge.Signature.PublicKey.KeyValue,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			peerId, err := peer.IDFromPublicKey(pk)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			altAddr, err := poseidon.HashBytes([]byte(peerId))
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			owner := &protobufs.AccountRef{}
			deleted := []*protobufs.TokenOutput{}
			for _, c := range t.Merge.Coins {
				coin, err := a.CoinStore.GetCoinByAddress(c.Address)
				if err != nil && !skipFailures {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(err, "apply transitions")
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				if !bytes.Equal(
					coin.Owner.GetImplicitAccount().Address,
					addr.FillBytes(make([]byte, 32)),
				) && !bytes.Equal(
					coin.Owner.GetImplicitAccount().Address,
					altAddr.FillBytes(make([]byte, 32)),
				) {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid owner"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				newTotal.Add(newTotal, new(big.Int).SetBytes(coin.Amount))
				for i := range coin.Intersection {
					newIntersection[i] |= coin.Intersection[i]
				}
				owner = coin.Owner
				deleted = append(deleted, &protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_DeletedCoin{
						DeletedCoin: coin,
					},
				})
			}
			newCoin.Amount = newTotal.FillBytes(make([]byte, 32))
			newCoin.Intersection = newIntersection
			newCoin.Owner = owner
			outputs.Outputs = append(outputs.Outputs, &protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: newCoin,
				},
			})
			outputs.Outputs = append(outputs.Outputs, deleted...)
			finalizedTransitions.Requests = append(
				finalizedTransitions.Requests,
				transition,
			)
		case *protobufs.TokenRequest_Split:
			newCoins := []*protobufs.Coin{}
			newAmounts := []*big.Int{}
			payload := []byte{}
			coin, err := a.CoinStore.GetCoinByAddress(t.Split.OfCoin.Address)
			if err != nil && !skipFailures {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(err, "apply transitions")
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			payload = append(payload, []byte("split")...)
			payload = append(payload, t.Split.OfCoin.Address...)
			for _, a := range t.Split.Amounts {
				payload = append(payload, a...)
			}

			if err := t.Split.Signature.Verify(payload); err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			addr, err := poseidon.HashBytes(t.Split.Signature.PublicKey.KeyValue)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			pk, err := pcrypto.UnmarshalEd448PublicKey(
				t.Split.Signature.PublicKey.KeyValue,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			peerId, err := peer.IDFromPublicKey(pk)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			altAddr, err := poseidon.HashBytes([]byte(peerId))
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			if !bytes.Equal(
				coin.Owner.GetImplicitAccount().Address,
				addr.FillBytes(make([]byte, 32)),
			) && !bytes.Equal(
				coin.Owner.GetImplicitAccount().Address,
				altAddr.FillBytes(make([]byte, 32)),
			) {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid owner"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			amounts := t.Split.Amounts
			total := new(big.Int)
			for _, amount := range amounts {
				amountBI := new(big.Int).SetBytes(amount)
				newAmounts = append(newAmounts, amountBI)
				total.Add(total, amountBI)
				newCoins = append(newCoins, &protobufs.Coin{
					Amount:       amountBI.FillBytes(make([]byte, 32)),
					Owner:        coin.Owner,
					Intersection: coin.Intersection,
				})
			}
			if new(big.Int).SetBytes(coin.Amount).Cmp(total) != 0 {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid split"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			for _, c := range newCoins {
				outputs.Outputs = append(outputs.Outputs, &protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Coin{
						Coin: c,
					},
				})
			}

			outputs.Outputs = append(
				outputs.Outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_DeletedCoin{
						DeletedCoin: coin,
					},
				},
			)
			finalizedTransitions.Requests = append(
				finalizedTransitions.Requests,
				transition,
			)
		case *protobufs.TokenRequest_Transfer:
			payload := []byte("transfer")
			coin, err := a.CoinStore.GetCoinByAddress(t.Transfer.OfCoin.Address)
			if err != nil && !skipFailures {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(err, "apply transitions")
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			payload = append(payload, t.Transfer.OfCoin.Address...)
			payload = append(
				payload,
				t.Transfer.ToAccount.GetImplicitAccount().Address...,
			)

			if err := t.Transfer.Signature.Verify(payload); err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			addr, err := poseidon.HashBytes(t.Transfer.Signature.PublicKey.KeyValue)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			pk, err := pcrypto.UnmarshalEd448PublicKey(
				t.Transfer.Signature.PublicKey.KeyValue,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			peerId, err := peer.IDFromPublicKey(pk)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			altAddr, err := poseidon.HashBytes([]byte(peerId))
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			if !bytes.Equal(
				coin.Owner.GetImplicitAccount().Address,
				addr.FillBytes(make([]byte, 32)),
			) && !bytes.Equal(
				coin.Owner.GetImplicitAccount().Address,
				altAddr.FillBytes(make([]byte, 32)),
			) {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid owner"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			newIntersection := coin.Intersection
			for i, b := range p2p.GetBloomFilter(
				addr.FillBytes(make([]byte, 32)),
				1024,
				3,
			) {
				newIntersection[i] |= b
			}

			outputs.Outputs = append(
				outputs.Outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Coin{
						Coin: &protobufs.Coin{
							Amount:       coin.Amount,
							Intersection: newIntersection,
							Owner:        t.Transfer.ToAccount,
						},
					},
				},
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_DeletedCoin{
						DeletedCoin: coin,
					},
				},
			)
			finalizedTransitions.Requests = append(
				finalizedTransitions.Requests,
				transition,
			)
		case *protobufs.TokenRequest_Mint:
			payload := []byte("mint")
			for _, p := range t.Mint.Proofs {
				payload = append(payload, p...)
			}
			if err := t.Mint.Signature.Verify(payload); err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}
			pk, err := pcrypto.UnmarshalEd448PublicKey(
				t.Mint.Signature.PublicKey.KeyValue,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			peerId, err := peer.IDFromPublicKey(pk)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			addr, err := poseidon.HashBytes(t.Mint.Signature.PublicKey.KeyValue)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						errors.New("invalid data"),
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}

			if len(t.Mint.Proofs) == 3 &&
				bytes.Equal(
					t.Mint.Proofs[0],
					[]byte("pre-dusk"),
				) && (bytes.Equal(t.Mint.Proofs[1], make([]byte, 32)) ||
				currentFrameNumber < 604800) {
				delete := []*protobufs.TokenOutput{}
				if !bytes.Equal(t.Mint.Proofs[1], make([]byte, 32)) {
					pre, err := a.CoinStore.GetPreCoinProofByAddress(t.Mint.Proofs[1])
					if err != nil {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								errors.New("invalid data"),
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
					}
					delete = append(delete, &protobufs.TokenOutput{
						Output: &protobufs.TokenOutput_DeletedProof{
							DeletedProof: pre,
						},
					})
				}

				data := t.Mint.Proofs[3]
				if len(data) < 28 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				increment := binary.BigEndian.Uint32(data[:4])
				parallelism := binary.BigEndian.Uint32(data[8:12])
				inputLen := binary.BigEndian.Uint64(data[12:20])

				if len(delete) != 0 {
					if delete[0].GetDeletedProof().Difficulty-1 != increment {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								errors.New("invalid data"),
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
					}
				}

				if uint64(len(data[20:])) < inputLen+8 {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				input := make([]byte, inputLen)
				copy(input[:], data[20:20+inputLen])

				outputLen := binary.BigEndian.Uint64(data[20+inputLen : 20+inputLen+8])

				if uint64(len(data[20+inputLen+8:])) < outputLen {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				output := make([]byte, outputLen)
				copy(output[:], data[20+inputLen+8:])
				dataProver := crypto.NewKZGInclusionProver(a.Logger)
				wesoProver := crypto.NewWesolowskiFrameProver(a.Logger)
				index := binary.BigEndian.Uint32(output[:4])
				indexProof := output[4:520]
				kzgCommitment := output[520:594]
				kzgProof := output[594:668]
				ip := sha3.Sum512(indexProof)

				v, err := dataProver.VerifyRaw(
					ip[:],
					kzgCommitment,
					int(index),
					kzgProof,
					nearestPowerOfTwo(uint64(parallelism)),
				)
				if err != nil {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				if !v {
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
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
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}

				pomwBasis := big.NewInt(1200000)

				reward := new(big.Int).Mul(pomwBasis, big.NewInt(int64(parallelism)))
				if len(delete) != 0 {
					reward.Add(
						reward,
						new(big.Int).SetBytes(delete[0].GetDeletedProof().Amount),
					)
				}

				if increment != 0 {
					add := &protobufs.PreCoinProof{
						Amount:      reward.FillBytes(make([]byte, 32)),
						Index:       index,
						IndexProof:  indexProof,
						Commitment:  kzgCommitment,
						Proof:       append(append([]byte{}, kzgProof...), indexProof...),
						Parallelism: parallelism,
						Difficulty:  increment,
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      addr.FillBytes(make([]byte, 32)),
								},
							},
						},
					}
					outputs.Outputs = append(outputs.Outputs, &protobufs.TokenOutput{
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
					outputs.Outputs = append(outputs.Outputs, &protobufs.TokenOutput{
						Output: &protobufs.TokenOutput_Coin{
							Coin: add,
						},
					})
				}
				outputs.Outputs = append(outputs.Outputs, delete...)
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
					if !skipFailures {
						return nil, nil, nil, errors.Wrap(
							errors.New("invalid data"),
							"apply transitions",
						)
					}
					failedTransitions.Requests = append(
						failedTransitions.Requests,
						transition,
					)
					break req
				}
				for _, p := range t.Mint.Proofs {
					if len(p) < 516+len(peerId)+8+32 {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								errors.New("invalid data"),
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
					}

					if !bytes.Equal(p[516:len(peerId)], []byte(peerId)) {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								errors.New("invalid data"),
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
					}

					wesoProver := crypto.NewWesolowskiFrameProver(a.Logger)

					frameNumber := binary.BigEndian.Uint64(
						p[516+len(peerId) : 516+len(peerId)+8],
					)
					if frameNumber > currentFrameNumber {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								errors.New("invalid data"),
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
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
									if !skipFailures {
										return nil, nil, nil, errors.Wrap(
											errors.New("invalid data"),
											"apply transitions",
										)
									}
									failedTransitions.Requests = append(
										failedTransitions.Requests,
										transition,
									)
									break req
								}
							}
						}
					}

					if !wesoProver.VerifyChallengeProof(p[516:], a.Difficulty, p[:516]) {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								errors.New("invalid data"),
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
					}

					scale := len(p2p.GetOnesIndices(p[516+len(peerId)+8 : 32]))
					if scale == 0 {
						if !skipFailures {
							return nil, nil, nil, errors.Wrap(
								errors.New("invalid data"),
								"apply transitions",
							)
						}
						failedTransitions.Requests = append(
							failedTransitions.Requests,
							transition,
						)
						break req
					}

					ringFactor := big.NewInt(2)
					ringFactor.Exp(ringFactor, big.NewInt(int64(ring)), nil)
					storage := big.NewInt(int64(1024 / (256 / scale)))
					unitFactor := big.NewInt(8000000000)
					storage.Mul(storage, unitFactor)
					storage.Quo(storage, ringFactor)

					outputs.Outputs = append(outputs.Outputs, &protobufs.TokenOutput{
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
					}, &protobufs.TokenOutput{
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
					})
				}
			}
			finalizedTransitions.Requests = append(
				finalizedTransitions.Requests,
				transition,
			)
		}
	}

	a.TokenOutputs = outputs

	return a, finalizedTransitions, failedTransitions, nil
}

func nearestPowerOfTwo(number uint64) uint64 {
	power := uint64(1)
	for number > power {
		power = power << 1
	}

	return power
}

func (a *TokenApplication) MaterializeStateFromApplication() (
	*protobufs.TokenOutputs,
	error,
) {
	var err error
	state := &protobufs.TokenOutputs{}
	if err != nil {
		return nil, errors.Wrap(err, "materialize state from application")
	}

	return state, nil
}
