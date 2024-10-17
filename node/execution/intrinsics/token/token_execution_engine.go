package token

import (
	"bytes"
	"crypto"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	gotime "time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/vdf"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type TokenExecutionEngine struct {
	logger                *zap.Logger
	clock                 *data.DataClockConsensusEngine
	clockStore            store.ClockStore
	coinStore             store.CoinStore
	keyStore              store.KeyStore
	keyManager            keys.KeyManager
	engineConfig          *config.EngineConfig
	pubSub                p2p.PubSub
	peerIdHash            []byte
	provingKey            crypto.Signer
	proverPublicKey       []byte
	provingKeyAddress     []byte
	inclusionProver       qcrypto.InclusionProver
	participantMx         sync.Mutex
	peerChannels          map[string]*p2p.PublicP2PChannel
	activeClockFrame      *protobufs.ClockFrame
	alreadyPublishedShare bool
	seenMessageMap        map[string]bool
	seenMessageMx         sync.Mutex
	intrinsicFilter       []byte
	frameProver           qcrypto.FrameProver
	peerSeniority         map[string]uint64
}

func NewTokenExecutionEngine(
	logger *zap.Logger,
	engineConfig *config.EngineConfig,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	frameProver qcrypto.FrameProver,
	inclusionProver qcrypto.InclusionProver,
	clockStore store.ClockStore,
	dataProofStore store.DataProofStore,
	coinStore store.CoinStore,
	masterTimeReel *time.MasterTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	keyStore store.KeyStore,
	report *protobufs.SelfTestReport,
) *TokenExecutionEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	seed, err := hex.DecodeString(engineConfig.GenesisSeed)
	if err != nil {
		panic(err)
	}

	intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

	_, _, err = clockStore.GetDataClockFrame(intrinsicFilter, 0, false)
	var origin []byte
	var inclusionProof *qcrypto.InclusionAggregateProof
	var proverKeys [][]byte
	var peerSeniority map[string]uint64
	genesisCreated := false

	if err != nil && errors.Is(err, store.ErrNotFound) {
		origin, inclusionProof, proverKeys, peerSeniority = CreateGenesisState(
			logger,
			engineConfig,
			nil,
			inclusionProver,
			coinStore,
		)
		genesisCreated = true
	} else if err != nil {
		panic(err)
	}

	dataTimeReel := time.NewDataTimeReel(
		intrinsicFilter,
		logger,
		clockStore,
		engineConfig,
		frameProver,
		origin,
		inclusionProof,
		proverKeys,
	)

	clock := data.NewDataClockConsensusEngine(
		engineConfig,
		logger,
		keyManager,
		clockStore,
		coinStore,
		keyStore,
		pubSub,
		frameProver,
		inclusionProver,
		masterTimeReel,
		dataTimeReel,
		peerInfoManager,
		report,
		intrinsicFilter,
		seed,
		peerSeniority,
	)

	e := &TokenExecutionEngine{
		logger:                logger,
		clock:                 clock,
		engineConfig:          engineConfig,
		keyManager:            keyManager,
		clockStore:            clockStore,
		coinStore:             coinStore,
		keyStore:              keyStore,
		pubSub:                pubSub,
		inclusionProver:       inclusionProver,
		frameProver:           frameProver,
		participantMx:         sync.Mutex{},
		peerChannels:          map[string]*p2p.PublicP2PChannel{},
		alreadyPublishedShare: false,
		seenMessageMx:         sync.Mutex{},
		seenMessageMap:        map[string]bool{},
		intrinsicFilter:       intrinsicFilter,
		peerSeniority:         peerSeniority,
	}

	peerId := e.pubSub.GetPeerID()
	addr, err := poseidon.HashBytes(peerId)
	if err != nil {
		panic(err)
	}

	addrBytes := addr.FillBytes(make([]byte, 32))
	e.peerIdHash = addrBytes
	provingKey, _, publicKeyBytes, provingKeyAddress := e.clock.GetProvingKey(
		engineConfig,
	)
	e.provingKey = provingKey
	e.proverPublicKey = publicKeyBytes
	e.provingKeyAddress = provingKeyAddress

	if genesisCreated {
		go func() {
			keys := [][]byte{}
			ksigs := [][]byte{}
			if len(e.engineConfig.MultisigProverEnrollmentPaths) != 0 {
				for _, conf := range e.engineConfig.MultisigProverEnrollmentPaths {
					extraConf, err := config.LoadConfig(conf, "", false)
					if err != nil {
						panic(err)
					}

					peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
					if err != nil {
						panic(errors.Wrap(err, "error unmarshaling peerkey"))
					}

					privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
					if err != nil {
						panic(errors.Wrap(err, "error unmarshaling peerkey"))
					}

					pub := privKey.GetPublic()
					pubBytes, err := pub.Raw()
					if err != nil {
						panic(errors.Wrap(err, "error unmarshaling peerkey"))
					}

					keys = append(keys, pubBytes)
					sig, err := privKey.Sign(e.pubSub.GetPublicKey())
					if err != nil {
						panic(errors.Wrap(err, "error unmarshaling peerkey"))
					}
					ksigs = append(ksigs, sig)
				}
			}

			keyjoin := []byte{}
			for _, k := range keys {
				keyjoin = append(keyjoin, k...)
			}

			mainsig, err := e.pubSub.SignMessage(keyjoin)
			if err != nil {
				panic(err)
			}

			announce := &protobufs.TokenRequest_Announce{
				Announce: &protobufs.AnnounceProverRequest{
					PublicKeySignaturesEd448: []*protobufs.Ed448Signature{},
				},
			}

			announce.Announce.PublicKeySignaturesEd448 = append(
				announce.Announce.PublicKeySignaturesEd448,
				&protobufs.Ed448Signature{
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: e.pubSub.GetPublicKey(),
					},
					Signature: mainsig,
				},
			)

			for i := range keys {
				announce.Announce.PublicKeySignaturesEd448 = append(
					announce.Announce.PublicKeySignaturesEd448,
					&protobufs.Ed448Signature{
						PublicKey: &protobufs.Ed448PublicKey{
							KeyValue: keys[i],
						},
						Signature: ksigs[i],
					},
				)
			}

			inc, _, _, err := dataProofStore.GetLatestDataTimeProof(
				e.pubSub.GetPeerID(),
			)
			_, parallelism, input, output, err := dataProofStore.GetDataTimeProof(
				e.pubSub.GetPeerID(),
				inc,
			)
			if err == nil {
				proof := []byte{}
				proof = binary.BigEndian.AppendUint32(proof, inc)
				proof = binary.BigEndian.AppendUint32(proof, parallelism)
				proof = binary.BigEndian.AppendUint64(proof, uint64(len(input)))
				proof = append(proof, input...)
				proof = binary.BigEndian.AppendUint64(proof, uint64(len(output)))
				proof = append(proof, output...)
				announce.Announce.InitialProof = &protobufs.MintCoinRequest{}
				announce.Announce.InitialProof.Proofs = [][]byte{
					[]byte("pre-dusk"),
					make([]byte, 32),
					proof,
				}
				payload := []byte("mint")
				for _, p := range announce.Announce.InitialProof.Proofs {
					payload = append(payload, p...)
				}
				sig, err := e.pubSub.SignMessage(payload)
				if err != nil {
					panic(err)
				}

				announce.Announce.InitialProof.Signature = &protobufs.Ed448Signature{
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: e.pubSub.GetPublicKey(),
					},
					Signature: sig,
				}
			}

			req := &protobufs.TokenRequest{
				Request: announce,
			}

			// need to wait for peering
			gotime.Sleep(30 * gotime.Second)
			e.publishMessage(intrinsicFilter, req)
		}()
	} else {
		f, _, err := e.clockStore.GetLatestDataClockFrame(e.intrinsicFilter)
		if err == nil {
			msg := []byte("resume")
			msg = binary.BigEndian.AppendUint64(msg, f.FrameNumber)
			msg = append(msg, e.intrinsicFilter...)
			sig, err := e.pubSub.SignMessage(msg)
			if err != nil {
				panic(err)
			}

			// need to wait for peering
			gotime.Sleep(30 * gotime.Second)
			e.publishMessage(e.intrinsicFilter, &protobufs.AnnounceProverResume{
				Filter:      e.intrinsicFilter,
				FrameNumber: f.FrameNumber,
				PublicKeySignatureEd448: &protobufs.Ed448Signature{
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: e.pubSub.GetPublicKey(),
					},
					Signature: sig,
				},
			})
		}
	}

	inc, _, _, err := dataProofStore.GetLatestDataTimeProof(pubSub.GetPeerID())
	if err != nil {
		go func() {
			addrBI, err := poseidon.HashBytes(pubSub.GetPeerID())
			if err != nil {
				panic(err)
			}

			addr := addrBI.FillBytes(make([]byte, 32))

			for {
				_, proofs, err := coinStore.GetPreCoinProofsForOwner(addr)
				if err == nil {
					for _, proof := range proofs {
						if proof.IndexProof != nil && len(proof.IndexProof) != 0 {
							if proof.Difficulty < inc {
								_, par, input, output, err := dataProofStore.GetDataTimeProof(
									pubSub.GetPeerID(),
									proof.Difficulty-1,
								)
								if err == nil {
									p := []byte{}
									p = binary.BigEndian.AppendUint32(p, proof.Difficulty-1)
									p = binary.BigEndian.AppendUint32(p, par)
									p = binary.BigEndian.AppendUint64(
										p,
										uint64(len(input)),
									)
									p = append(p, input...)
									p = binary.BigEndian.AppendUint64(p, uint64(len(output)))
									p = append(p, output...)
									proofs := [][]byte{
										[]byte("pre-dusk"),
										make([]byte, 32),
										p,
									}
									payload := []byte("mint")
									for _, i := range proofs {
										payload = append(payload, i...)
									}
									sig, err := e.pubSub.SignMessage(payload)
									if err != nil {
										panic(err)
									}
									e.publishMessage(e.intrinsicFilter, &protobufs.TokenRequest{
										Request: &protobufs.TokenRequest_Mint{
											Mint: &protobufs.MintCoinRequest{
												Proofs: proofs,
												Signature: &protobufs.Ed448Signature{
													PublicKey: &protobufs.Ed448PublicKey{
														KeyValue: e.pubSub.GetPublicKey(),
													},
													Signature: sig,
												},
											},
										},
									})
								}
							}
						}
					}
				}
				gotime.Sleep(10 * gotime.Second)
			}
		}()
	}

	return e
}

var _ execution.ExecutionEngine = (*TokenExecutionEngine)(nil)

// GetName implements ExecutionEngine
func (*TokenExecutionEngine) GetName() string {
	return "Token"
}

// GetSupportedApplications implements ExecutionEngine
func (
	*TokenExecutionEngine,
) GetSupportedApplications() []*protobufs.Application {
	return []*protobufs.Application{
		{
			Address:          application.TOKEN_ADDRESS,
			ExecutionContext: protobufs.ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
		},
	}
}

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

		address, err := GetAddressOfCoin(output.GetCoin(), 0)
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

func GetAddressOfCoin(
	coin *protobufs.Coin,
	frameNumber uint64,
) ([]byte, error) {
	eval := []byte{}
	eval = append(eval, application.TOKEN_ADDRESS...)
	eval = binary.BigEndian.AppendUint64(eval, frameNumber)
	eval = append(eval, coin.Amount...)
	eval = append(eval, coin.Intersection...)
	eval = binary.BigEndian.AppendUint32(eval, 0)
	eval = append(eval, coin.Owner.GetImplicitAccount().Address...)
	addressBI, err := poseidon.HashBytes(eval)
	if err != nil {
		return nil, err
	}

	return addressBI.FillBytes(make([]byte, 32)), nil
}

func GetAddressOfPreCoinProof(
	proof *protobufs.PreCoinProof,
) ([]byte, error) {
	eval := []byte{}
	eval = append(eval, application.TOKEN_ADDRESS...)
	eval = append(eval, proof.Amount...)
	eval = binary.BigEndian.AppendUint32(eval, proof.Index)
	eval = append(eval, proof.IndexProof...)
	eval = append(eval, proof.Commitment...)
	eval = append(eval, proof.Proof...)
	eval = binary.BigEndian.AppendUint32(eval, proof.Parallelism)
	eval = binary.BigEndian.AppendUint32(eval, proof.Difficulty)
	eval = binary.BigEndian.AppendUint32(eval, 0)
	eval = append(eval, proof.Owner.GetImplicitAccount().Address...)
	addressBI, err := poseidon.HashBytes(eval)
	if err != nil {
		return nil, err
	}

	return addressBI.FillBytes(make([]byte, 32)), nil
}

// Start implements ExecutionEngine
func (e *TokenExecutionEngine) Start() <-chan error {
	errChan := make(chan error)

	go func() {
		err := <-e.clock.Start()
		if err != nil {
			panic(err)
		}

		err = <-e.clock.RegisterExecutor(e, 0)
		if err != nil {
			panic(err)
		}

		go e.RunWorker()

		errChan <- nil
	}()

	return errChan
}

// Stop implements ExecutionEngine
func (e *TokenExecutionEngine) Stop(force bool) <-chan error {
	errChan := make(chan error)

	go func() {
		errChan <- <-e.clock.Stop(force)
	}()

	return errChan
}

// ProcessMessage implements ExecutionEngine
func (e *TokenExecutionEngine) ProcessMessage(
	address []byte,
	message *protobufs.Message,
) ([]*protobufs.Message, error) {
	if bytes.Equal(address, e.GetSupportedApplications()[0].Address) {
		e.logger.Debug("processing execution message")
		any := &anypb.Any{}
		if err := proto.Unmarshal(message.Payload, any); err != nil {
			return nil, errors.Wrap(err, "process message")
		}

		switch any.TypeUrl {
		case protobufs.ClockFrameType:
			frame := &protobufs.ClockFrame{}
			if err := any.UnmarshalTo(frame); err != nil {
				return nil, errors.Wrap(err, "process message")
			}

			if frame.FrameNumber < e.clock.GetFrame().FrameNumber {
				return nil, nil
			}

			if err := e.frameProver.VerifyDataClockFrame(frame); err != nil {
				return nil, errors.Wrap(err, "process message")
			}

			if err := e.VerifyExecution(frame); err != nil {
				return nil, errors.Wrap(err, "process message")
			}
		case protobufs.TokenRequestType:
			hash := sha3.Sum256(any.Value)
			if any.TypeUrl == protobufs.TokenRequestType {
				e.seenMessageMx.Lock()
				ref := string(hash[:])
				if _, ok := e.seenMessageMap[ref]; !ok {
					e.seenMessageMap[ref] = true
				} else {
					return nil, errors.Wrap(
						errors.New("message already received"),
						"process message",
					)
				}
				e.seenMessageMx.Unlock()
			}
			if e.clock.IsInProverTrie(e.proverPublicKey) {
				payload, err := proto.Marshal(any)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				h, err := poseidon.HashBytes(payload)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				msg := &protobufs.Message{
					Hash:    h.Bytes(),
					Address: e.provingKeyAddress,
					Payload: payload,
				}
				return []*protobufs.Message{
					msg,
				}, nil
			}
		}
	}

	return nil, nil
}

func (e *TokenExecutionEngine) RunWorker() {
	frameChan := e.clock.GetFrameChannel()
	for {
		select {
		case frame := <-frameChan:
			e.activeClockFrame = frame
			e.logger.Info(
				"evaluating next frame",
				zap.Uint64(
					"frame_number",
					frame.FrameNumber,
				),
			)
			app, err := application.MaterializeApplicationFromFrame(
				frame,
				e.clock.GetFrameProverTries(),
				e.coinStore,
				e.logger,
			)
			if err != nil {
				e.logger.Error(
					"error while materializing application from frame",
					zap.Error(err),
				)
				panic(err)
			}

			txn, err := e.coinStore.NewTransaction()
			if err != nil {
				panic(err)
			}

			for _, output := range app.TokenOutputs.Outputs {
				switch o := output.Output.(type) {
				case *protobufs.TokenOutput_Coin:
					address, err := GetAddressOfCoin(o.Coin, frame.FrameNumber)
					if err != nil {
						panic(err)
					}
					err = e.coinStore.PutCoin(
						txn,
						frame.FrameNumber,
						address,
						o.Coin,
					)
					if err != nil {
						panic(err)
					}
				case *protobufs.TokenOutput_DeletedCoin:
					coin, err := e.coinStore.GetCoinByAddress(o.DeletedCoin.Address)
					if err != nil {
						panic(err)
					}
					err = e.coinStore.DeleteCoin(
						txn,
						o.DeletedCoin.Address,
						coin,
					)
					if err != nil {
						panic(err)
					}
				case *protobufs.TokenOutput_Proof:
					address, err := GetAddressOfPreCoinProof(o.Proof)
					if err != nil {
						panic(err)
					}
					err = e.coinStore.PutPreCoinProof(
						txn,
						frame.FrameNumber,
						address,
						o.Proof,
					)
					if err != nil {
						panic(err)
					}
				case *protobufs.TokenOutput_DeletedProof:
					address, err := GetAddressOfPreCoinProof(o.DeletedProof)
					if err != nil {
						panic(err)
					}
					err = e.coinStore.DeletePreCoinProof(
						txn,
						address,
						o.DeletedProof,
					)
					if err != nil {
						panic(err)
					}
				}
			}

			if err := txn.Commit(); err != nil {
				panic(err)
			}
		}
	}
}

func (e *TokenExecutionEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	any.TypeUrl = strings.Replace(
		any.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(any)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: application.TOKEN_ADDRESS,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}

func (e *TokenExecutionEngine) VerifyExecution(
	frame *protobufs.ClockFrame,
) error {
	if e.clock.GetFrame().FrameNumber != frame.FrameNumber-1 {
		return nil
	}

	if len(frame.AggregateProofs) > 0 {
		for _, proofs := range frame.AggregateProofs {
			for _, inclusion := range proofs.InclusionCommitments {
				if inclusion.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					transition, _, err := application.GetOutputsFromClockFrame(frame)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					parent, err := e.clockStore.GetStagedDataClockFrame(
						append(
							p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3),
						),
						frame.FrameNumber-1,
						frame.ParentSelector,
						false,
					)
					if err != nil && !errors.Is(err, store.ErrNotFound) {
						return errors.Wrap(err, "verify execution")
					}

					if parent == nil {
						return errors.Wrap(
							errors.New("missing parent frame"),
							"verify execution",
						)
					}

					a, err := application.MaterializeApplicationFromFrame(
						parent,
						e.clock.GetFrameProverTries(),
						e.coinStore,
						e.logger,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a, _, _, err = a.ApplyTransitions(frame.FrameNumber, transition, false)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a2, err := application.MaterializeApplicationFromFrame(
						frame,
						e.clock.GetFrameProverTries(),
						e.coinStore,
						e.logger,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					if len(a.TokenOutputs.Outputs) != len(a2.TokenOutputs.Outputs) {
						return errors.Wrap(
							application.ErrInvalidStateTransition,
							"verify execution",
						)
					}

					for i := range a.TokenOutputs.Outputs {
						o1 := a.TokenOutputs.Outputs[i]
						o2 := a2.TokenOutputs.Outputs[i]
						b1, err := proto.Marshal(o1)
						if err != nil {
							return errors.Wrap(
								application.ErrInvalidStateTransition,
								"verify execution",
							)
						}
						b2, err := proto.Marshal(o2)
						if err != nil {
							return errors.Wrap(
								application.ErrInvalidStateTransition,
								"verify execution",
							)
						}
						if !bytes.Equal(b1, b2) {
							return errors.Wrap(
								application.ErrInvalidStateTransition,
								"verify execution",
							)
						}
					}

					return nil
				}
			}
		}
	}

	return nil
}

func (e *TokenExecutionEngine) GetPeerInfo() *protobufs.PeerInfoResponse {
	return e.clock.GetPeerInfo()
}

func (e *TokenExecutionEngine) GetFrame() *protobufs.ClockFrame {
	return e.clock.GetFrame()
}
