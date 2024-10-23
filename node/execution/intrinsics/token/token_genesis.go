package token

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/mr-tron/base58"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/vdf"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var BridgeAddress = "1ac3290d57e064bdb5a57e874b59290226a9f9730d69f1d963600883789d6ee2"

type BridgedPeerJson struct {
	Amount     string `json:"amount"`
	Identifier string `json:"identifier"`
	Variant    string `json:"variant"`
}

type FirstRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}

type SecondRetroJson struct {
	PeerId      string `json:"peerId"`
	Reward      string `json:"reward"`
	JanPresence bool   `json:"janPresence"`
	FebPresence bool   `json:"febPresence"`
	MarPresence bool   `json:"marPresence"`
	AprPresence bool   `json:"aprPresence"`
	MayPresence bool   `json:"mayPresence"`
}

type ThirdRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}

type FourthRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}

//go:embed bridged.json
var bridgedPeersJsonBinary []byte

//go:embed ceremony_vouchers.json
var ceremonyVouchersJsonBinary []byte

//go:embed first_retro.json
var firstRetroJsonBinary []byte

//go:embed second_retro.json
var secondRetroJsonBinary []byte

//go:embed third_retro.json
var thirdRetroJsonBinary []byte

//go:embed fourth_retro.json
var fourthRetroJsonBinary []byte

// Creates a genesis state for the intrinsic
func CreateGenesisState(
	logger *zap.Logger,
	engineConfig *config.EngineConfig,
	testProverKeys [][]byte,
	inclusionProver qcrypto.InclusionProver,
	coinStore store.CoinStore,
	network uint,
) (
	[]byte,
	*qcrypto.InclusionAggregateProof,
	[][]byte,
	map[string]uint64,
) {
	genesis := config.GetGenesis()
	if genesis == nil {
		panic("genesis is nil")
	}

	seed, err := hex.DecodeString(engineConfig.GenesisSeed)
	if err != nil {
		panic(err)
	}

	logger.Info("creating genesis frame from message:")
	for i, l := range strings.Split(string(seed), "|") {
		if i == 0 {
			logger.Info(l)
		} else {
			logger.Info(fmt.Sprintf("Blockstamp ending in 0x%x", l))
		}
	}

	difficulty := engineConfig.Difficulty
	if difficulty != 200000 {
		difficulty = 200000
	}

	b := sha3.Sum256(seed)
	v := vdf.New(difficulty, b)

	v.Execute()
	o := v.GetOutput()
	inputMessage := o[:]

	logger.Info("encoding all prior state")

	if network == 0 {
		bridged := []*BridgedPeerJson{}
		vouchers := []string{}
		firstRetro := []*FirstRetroJson{}
		secondRetro := []*SecondRetroJson{}
		thirdRetro := []*ThirdRetroJson{}
		fourthRetro := []*FourthRetroJson{}

		err = json.Unmarshal(bridgedPeersJsonBinary, &bridged)
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(ceremonyVouchersJsonBinary, &vouchers)
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(firstRetroJsonBinary, &firstRetro)
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(secondRetroJsonBinary, &secondRetro)
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(thirdRetroJsonBinary, &thirdRetro)
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(fourthRetroJsonBinary, &fourthRetro)
		if err != nil {
			panic(err)
		}

		bridgedAddrs := map[string]struct{}{}

		logger.Info("encoding bridged token state")
		bridgeTotal := decimal.Zero
		for _, b := range bridged {
			amt, err := decimal.NewFromString(b.Amount)
			if err != nil {
				panic(err)
			}
			bridgeTotal = bridgeTotal.Add(amt)
			bridgedAddrs[b.Identifier] = struct{}{}
		}

		voucherTotals := map[string]decimal.Decimal{}
		peerIdTotals := map[string]decimal.Decimal{}
		peerSeniority := map[string]uint64{}
		logger.Info("encoding first retro state")
		for _, f := range firstRetro {
			if _, ok := bridgedAddrs[f.PeerId]; !ok {
				peerIdTotals[f.PeerId], err = decimal.NewFromString(f.Reward)
				if err != nil {
					panic(err)
				}
			}

			// these don't have decimals so we can shortcut
			max := 157208
			actual, err := strconv.Atoi(f.Reward)
			if err != nil {
				panic(err)
			}

			peerSeniority[f.PeerId] = uint64(10 * 6 * 60 * 24 * 92 / (max / actual))
		}

		logger.Info("encoding voucher state")
		for _, v := range vouchers {
			if _, ok := bridgedAddrs[v]; !ok {
				voucherTotals[v] = decimal.NewFromInt(50)
			}
		}

		logger.Info("encoding second retro state")
		for _, f := range secondRetro {
			if _, ok := bridgedAddrs[f.PeerId]; !ok {
				existing, ok := peerIdTotals[f.PeerId]

				amount, err := decimal.NewFromString(f.Reward)
				if err != nil {
					panic(err)
				}

				if !ok {
					peerIdTotals[f.PeerId] = amount
				} else {
					peerIdTotals[f.PeerId] = existing.Add(amount)
				}
			}

			if _, ok := peerSeniority[f.PeerId]; !ok {
				peerSeniority[f.PeerId] = 0
			}

			if f.JanPresence {
				peerSeniority[f.PeerId] = peerSeniority[f.PeerId] + (10 * 6 * 60 * 24 * 31)
			}

			if f.FebPresence {
				peerSeniority[f.PeerId] = peerSeniority[f.PeerId] + (10 * 6 * 60 * 24 * 29)
			}

			if f.MarPresence {
				peerSeniority[f.PeerId] = peerSeniority[f.PeerId] + (10 * 6 * 60 * 24 * 31)
			}

			if f.AprPresence {
				peerSeniority[f.PeerId] = peerSeniority[f.PeerId] + (10 * 6 * 60 * 24 * 30)
			}

			if f.MayPresence {
				peerSeniority[f.PeerId] = peerSeniority[f.PeerId] + (10 * 6 * 60 * 24 * 31)
			}
		}

		logger.Info("encoding third retro state")
		for _, f := range thirdRetro {
			existing, ok := peerIdTotals[f.PeerId]

			amount, err := decimal.NewFromString(f.Reward)
			if err != nil {
				panic(err)
			}

			if !ok {
				peerIdTotals[f.PeerId] = amount
			} else {
				peerIdTotals[f.PeerId] = existing.Add(amount)
			}

			if _, ok := peerSeniority[f.PeerId]; !ok {
				peerSeniority[f.PeerId] = 0
			}

			peerSeniority[f.PeerId] = peerSeniority[f.PeerId] + (10 * 6 * 60 * 24 * 30)
		}

		logger.Info("encoding fourth retro state")
		for _, f := range fourthRetro {
			existing, ok := peerIdTotals[f.PeerId]

			amount, err := decimal.NewFromString(f.Reward)
			if err != nil {
				panic(err)
			}

			if !ok {
				peerIdTotals[f.PeerId] = amount
			} else {
				peerIdTotals[f.PeerId] = existing.Add(amount)
			}

			if _, ok := peerSeniority[f.PeerId]; !ok {
				peerSeniority[f.PeerId] = 0
			}

			peerSeniority[f.PeerId] = peerSeniority[f.PeerId] + (10 * 6 * 60 * 24 * 31)
		}

		genesisState := &protobufs.TokenOutputs{
			Outputs: []*protobufs.TokenOutput{},
		}

		factor, _ := decimal.NewFromString("8000000000")
		bridgeAddressHex, err := hex.DecodeString(BridgeAddress)
		if err != nil {
			panic(err)
		}

		totalExecutions := 0
		logger.Info(
			"creating execution state",
			zap.Int(
				"coin_executions",
				totalExecutions,
			),
		)
		genesisState.Outputs = append(genesisState.Outputs, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: &protobufs.Coin{
					Amount: bridgeTotal.Mul(factor).BigInt().FillBytes(
						make([]byte, 32),
					),
					Intersection: make([]byte, 1024),
					Owner: &protobufs.AccountRef{
						Account: &protobufs.AccountRef_ImplicitAccount{
							ImplicitAccount: &protobufs.ImplicitAccount{
								Address: bridgeAddressHex,
							},
						},
					},
				},
			},
		})
		totalExecutions++

		for peerId, total := range peerIdTotals {
			if totalExecutions%1000 == 0 {
				logger.Info(
					"creating execution state",
					zap.Int(
						"coin_executions",
						totalExecutions,
					),
				)
			}
			peerBytes, err := base58.Decode(peerId)
			if err != nil {
				panic(err)
			}

			addr, err := poseidon.HashBytes(peerBytes)
			if err != nil {
				panic(err)
			}

			genesisState.Outputs = append(genesisState.Outputs, &protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: &protobufs.Coin{
						Amount: total.Mul(factor).BigInt().FillBytes(
							make([]byte, 32),
						),
						Intersection: make([]byte, 1024),
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									Address: addr.FillBytes(make([]byte, 32)),
								},
							},
						},
					},
				},
			})
			totalExecutions++
		}

		for voucher, total := range voucherTotals {
			if totalExecutions%1000 == 0 {
				logger.Info(
					"creating execution state",
					zap.Int(
						"coin_executions",
						totalExecutions,
					),
				)
			}
			keyBytes, err := hex.DecodeString(voucher[2:])
			if err != nil {
				panic(err)
			}

			addr, err := poseidon.HashBytes(keyBytes)
			if err != nil {
				panic(err)
			}

			genesisState.Outputs = append(genesisState.Outputs, &protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: &protobufs.Coin{
						Amount: total.Mul(factor).BigInt().FillBytes(
							make([]byte, 32),
						),
						Intersection: make([]byte, 1024),
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									Address: addr.FillBytes(make([]byte, 32)),
								},
							},
						},
					},
				},
			})
			totalExecutions++
		}

		logger.Info(
			"serializing execution state to store, this may take some time...",
			zap.Int(
				"coin_executions",
				totalExecutions,
			),
		)
		txn, err := coinStore.NewTransaction()
		for _, output := range genesisState.Outputs {
			if err != nil {
				panic(err)
			}

			address, err := GetAddressOfCoin(output.GetCoin(), 0, 0)
			if err != nil {
				panic(err)
			}
			err = coinStore.PutCoin(
				txn,
				0,
				address,
				output.GetCoin(),
			)
			if err != nil {
				panic(err)
			}
		}
		if err := txn.Commit(); err != nil {
			panic(err)
		}

		logger.Info("encoded transcript")

		outputBytes, err := proto.Marshal(genesisState)
		if err != nil {
			panic(err)
		}

		intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

		executionOutput := &protobufs.IntrinsicExecutionOutput{
			Address: intrinsicFilter,
			Output:  outputBytes,
			Proof:   seed,
		}

		data, err := proto.Marshal(executionOutput)
		if err != nil {
			panic(err)
		}

		logger.Debug("encoded execution output")
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

		commitment, err := inclusionProver.CommitRaw(
			expand,
			16,
		)
		if err != nil {
			panic(err)
		}

		logger.Debug("creating kzg proof")
		proof, err := inclusionProver.ProveRaw(
			expand,
			int(expand[0]%16),
			16,
		)
		if err != nil {
			panic(err)
		}

		logger.Info("finalizing execution proof")

		return inputMessage, &qcrypto.InclusionAggregateProof{
			InclusionCommitments: []*qcrypto.InclusionCommitment{
				&qcrypto.InclusionCommitment{
					TypeUrl:    protobufs.IntrinsicExecutionOutputType,
					Data:       data,
					Commitment: commitment,
				},
			},
			AggregateCommitment: commitment,
			Proof:               proof,
		}, [][]byte{genesis.Beacon}, map[string]uint64{}
	} else {
		logger.Info(
			"THIS IS A TESTNET GENESIS, DO NOT CONNECT THIS NODE TO MAINNET",
		)

		genesisState := &protobufs.TokenOutputs{
			Outputs: []*protobufs.TokenOutput{},
		}

		addr, err := poseidon.HashBytes(genesis.Beacon)
		if err != nil {
			panic(err)
		}

		factor, _ := new(big.Int).SetString("8000000000", 10)

		genesisState.Outputs = append(genesisState.Outputs, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: &protobufs.Coin{
					Amount: factor.Mul(factor, big.NewInt(0x0fffffff)).FillBytes(
						make([]byte, 32),
					),
					Intersection: make([]byte, 1024),
					Owner: &protobufs.AccountRef{
						Account: &protobufs.AccountRef_ImplicitAccount{
							ImplicitAccount: &protobufs.ImplicitAccount{
								Address: addr.FillBytes(make([]byte, 32)),
							},
						},
					},
				},
			},
		})

		logger.Info("serializing execution state to store")
		txn, err := coinStore.NewTransaction()
		for _, output := range genesisState.Outputs {
			if err != nil {
				panic(err)
			}

			address, err := GetAddressOfCoin(output.GetCoin(), 0, 0)
			if err != nil {
				panic(err)
			}
			err = coinStore.PutCoin(
				txn,
				0,
				address,
				output.GetCoin(),
			)
			if err != nil {
				panic(err)
			}
		}
		if err := txn.Commit(); err != nil {
			panic(err)
		}

		logger.Info("encoded transcript")

		outputBytes, err := proto.Marshal(genesisState)
		if err != nil {
			panic(err)
		}

		intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

		executionOutput := &protobufs.IntrinsicExecutionOutput{
			Address: intrinsicFilter,
			Output:  outputBytes,
			Proof:   seed,
		}

		data, err := proto.Marshal(executionOutput)
		if err != nil {
			panic(err)
		}

		logger.Debug("encoded execution output")
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

		commitment, err := inclusionProver.CommitRaw(
			expand,
			16,
		)
		if err != nil {
			panic(err)
		}

		logger.Debug("creating kzg proof")
		proof, err := inclusionProver.ProveRaw(
			expand,
			int(expand[0]%16),
			16,
		)
		if err != nil {
			panic(err)
		}

		logger.Info("finalizing execution proof")

		return inputMessage, &qcrypto.InclusionAggregateProof{
			InclusionCommitments: []*qcrypto.InclusionCommitment{
				&qcrypto.InclusionCommitment{
					TypeUrl:    protobufs.IntrinsicExecutionOutputType,
					Data:       data,
					Commitment: commitment,
				},
			},
			AggregateCommitment: commitment,
			Proof:               proof,
		}, [][]byte{genesis.Beacon}, map[string]uint64{}
	}
}
