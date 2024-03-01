//go:build !js && !wasm

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pbnjay/memory"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
)

var (
	configDirectory = flag.String(
		"config",
		filepath.Join(".", ".config"),
		"the configuration directory",
	)
	balance = flag.Bool(
		"balance",
		false,
		"print the node's confirmed token balance to stdout and exit",
	)
	dbConsole = flag.Bool(
		"db-console",
		false,
		"starts the node in database console mode",
	)
	importPrivKey = flag.String(
		"import-priv-key",
		"",
		"creates a new config using a specific key from the phase one ceremony",
	)
	peerId = flag.Bool(
		"peer-id",
		false,
		"print the peer id to stdout from the config and exit",
	)
	memprofile = flag.String(
		"memprofile",
		"",
		"write memory profile after 20m to this file",
	)
)

func main() {
	flag.Parse()

	if *memprofile != "" {
		go func() {
			for {
				time.Sleep(5 * time.Minute)
				f, err := os.Create(*memprofile)
				if err != nil {
					log.Fatal(err)
				}
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		}()
	}

	if *balance {
		config, err := config.LoadConfig(*configDirectory, "")
		if err != nil {
			panic(err)
		}

		if config.ListenGRPCMultiaddr == "" {
			_, _ = fmt.Fprintf(os.Stderr, "gRPC Not Enabled, Please Configure\n")
			os.Exit(1)
		}

		conn, err := app.ConnectToNode(config)
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)

		balance, err := app.FetchTokenBalance(client)
		if err != nil {
			panic(err)
		}

		fmt.Println("Owned balance:", balance.Owned, "QUIL")
		fmt.Println("Unconfirmed balance:", balance.UnconfirmedOwned, "QUIL")

		return
	}

	if *peerId {
		config, err := config.LoadConfig(*configDirectory, "")
		if err != nil {
			panic(err)
		}

		printPeerID(config.P2P)
		return
	}

	if *importPrivKey != "" {
		config, err := config.LoadConfig(*configDirectory, *importPrivKey)
		if err != nil {
			panic(err)
		}

		printPeerID(config.P2P)
		fmt.Println("Import completed, you are ready for the launch.")
		return
	}
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	if !*dbConsole {
		printLogo()
		printVersion()
		fmt.Println(" ")
	}

	nodeConfig, err := config.LoadConfig(*configDirectory, "")
	if err != nil {
		panic(err)
	}

	clearIfTestData(*configDirectory, nodeConfig)
	migrate(*configDirectory, nodeConfig)

	if *dbConsole {
		console, err := app.NewDBConsole(nodeConfig)
		if err != nil {
			panic(err)
		}

		console.Run()
		return
	}

	fmt.Println("Loading ceremony state and starting node...")
	kzg.Init()

	report := RunSelfTestIfNeeded(*configDirectory, nodeConfig)

	node, err := app.NewNode(nodeConfig, report)
	if err != nil {
		panic(err)
	}

	if nodeConfig.ListenGRPCMultiaddr != "" {
		srv, err := rpc.NewRPCServer(
			nodeConfig.ListenGRPCMultiaddr,
			nodeConfig.ListenRestMultiaddr,
			node.GetLogger(),
			node.GetClockStore(),
			node.GetKeyManager(),
			node.GetPubSub(),
			node.GetExecutionEngines(),
		)
		if err != nil {
			panic(err)
		}

		go func() {
			err := srv.Start()
			if err != nil {
				panic(err)
			}
		}()
	}

	node.Start()

	<-done
	node.Stop()
}

func RunSelfTestIfNeeded(
	configDir string,
	nodeConfig *config.Config,
) *protobufs.SelfTestReport {
	logger, _ := zap.NewProduction()

	cores := runtime.GOMAXPROCS(0)
	memory := memory.TotalMemory()
	f, err := os.Stat(filepath.Join(configDir, "SELF_TEST"))

	if f != nil {
		if f.Size() != 0 {
			report := &protobufs.SelfTestReport{}

			selfTestBytes, err := os.ReadFile(filepath.Join(configDir, "SELF_TEST"))
			if err != nil {
				panic(err)
			}

			err = proto.Unmarshal(selfTestBytes, report)
			if err != nil {
				panic(err)
			}

			if report.Cores == uint32(cores) &&
				binary.BigEndian.Uint64(report.Memory) == memory {
				return report
			}
		}
		logger.Info("no self-test report found, generating")
	}

	report := &protobufs.SelfTestReport{}
	difficulty := nodeConfig.Engine.Difficulty
	if difficulty == 0 {
		difficulty = 10000
	}
	report.Difficulty = difficulty

	frameProver := qcrypto.NewWesolowskiFrameProver(logger)

	logger.Info("generating difficulty metric")

	start := time.Now().UnixMilli()
	_, err = frameProver.ProveMasterClockFrame(
		&protobufs.ClockFrame{
			Filter:         []byte{0x00},
			FrameNumber:    0,
			Timestamp:      0,
			Difficulty:     difficulty,
			ParentSelector: []byte{0x00},
			Input:          make([]byte, 516),
			Output:         make([]byte, 516),
		},
		0,
		difficulty,
	)
	if err != nil {
		panic(err)
	}
	end := time.Now().UnixMilli()
	report.DifficultyMetric = end - start

	logger.Info("generating entropy for commit/proof sizes")

	p16bytes := make([]byte, 1024)
	p128bytes := make([]byte, 8192)
	p1024bytes := make([]byte, 65536)
	p65536bytes := make([]byte, 4194304)
	rand.Read(p16bytes)
	rand.Read(p128bytes)
	rand.Read(p1024bytes)
	rand.Read(p65536bytes)
	kzgProver := kzg.DefaultKZGProver()

	p16, _ := kzgProver.BytesToPolynomial(p16bytes)
	p128, _ := kzgProver.BytesToPolynomial(p128bytes)
	p1024, _ := kzgProver.BytesToPolynomial(p1024bytes)
	p65536, _ := kzgProver.BytesToPolynomial(p65536bytes)

	logger.Info("generating 16 degree commitment metric")
	start = time.Now().UnixMilli()
	c16, err := kzgProver.Commit(p16)
	if err != nil {
		panic(err)
	}
	end = time.Now().UnixMilli()
	report.Commit_16Metric = end - start

	logger.Info("generating 128 degree commitment metric")
	start = time.Now().UnixMilli()
	c128, err := kzgProver.Commit(p128)
	if err != nil {
		panic(err)
	}
	end = time.Now().UnixMilli()
	report.Commit_128Metric = end - start

	logger.Info("generating 1024 degree commitment metric")
	start = time.Now().UnixMilli()
	c1024, err := kzgProver.Commit(p1024)
	if err != nil {
		panic(err)
	}
	end = time.Now().UnixMilli()
	report.Commit_1024Metric = end - start

	logger.Info("generating 65536 degree commitment metric")
	start = time.Now().UnixMilli()
	c65536, err := kzgProver.Commit(p65536)
	if err != nil {
		panic(err)
	}
	end = time.Now().UnixMilli()
	report.Commit_65536Metric = end - start

	logger.Info("generating 16 degree proof metric")
	start = time.Now().UnixMilli()
	_, err = kzgProver.Prove(p16, c16, p16[0])
	if err != nil {
		panic(err)
	}
	end = time.Now().UnixMilli()
	report.Proof_16Metric = end - start

	logger.Info("generating 128 degree proof metric")
	start = time.Now().UnixMilli()
	_, err = kzgProver.Prove(p128, c128, p128[0])
	if err != nil {
		panic(err)
	}
	end = time.Now().UnixMilli()
	report.Proof_128Metric = end - start

	logger.Info("generating 1024 degree proof metric")
	start = time.Now().UnixMilli()
	_, err = kzgProver.Prove(p1024, c1024, p1024[0])
	if err != nil {
		panic(err)
	}
	end = time.Now().UnixMilli()
	report.Proof_1024Metric = end - start

	logger.Info("generating 65536 degree proof metric")
	start = time.Now().UnixMilli()
	_, err = kzgProver.Prove(p65536, c65536, p65536[0])
	if err != nil {
		panic(err)
	}
	end = time.Now().UnixMilli()
	report.Proof_65536Metric = end - start

	report.Cores = uint32(cores)
	report.Memory = binary.BigEndian.AppendUint64([]byte{}, memory)
	disk := utils.GetDiskSpace(nodeConfig.DB.Path)
	report.Storage = binary.BigEndian.AppendUint64([]byte{}, disk)
	logger.Info("writing report")

	// tag: dusk – capabilities report in v1.5
	reportBytes, err := proto.Marshal(report)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(
		filepath.Join(configDir, "SELF_TEST"),
		reportBytes,
		fs.FileMode(0600),
	)
	if err != nil {
		panic(err)
	}

	return report
}

func clearIfTestData(configDir string, nodeConfig *config.Config) {
	_, err := os.Stat(filepath.Join(configDir, "RELEASE_VERSION"))
	if os.IsNotExist(err) {
		fmt.Println("Clearing test data...")
		err := os.RemoveAll(nodeConfig.DB.Path)
		if err != nil {
			panic(err)
		}

		versionFile, err := os.OpenFile(
			filepath.Join(configDir, "RELEASE_VERSION"),
			os.O_CREATE|os.O_RDWR,
			fs.FileMode(0600),
		)
		if err != nil {
			panic(err)
		}

		_, err = versionFile.Write([]byte{0x01, 0x00, 0x00})
		if err != nil {
			panic(err)
		}

		err = versionFile.Close()
		if err != nil {
			panic(err)
		}
	}
}

func migrate(configDir string, nodeConfig *config.Config) {
	_, err := os.Stat(filepath.Join(configDir, "MIGRATIONS"))
	if os.IsNotExist(err) {
		fmt.Println("Deduplicating and compressing clock frame data...")
		clock, err := app.NewClockStore(nodeConfig)
		if err := clock.Deduplicate(application.CEREMONY_ADDRESS); err != nil {
			panic(err)
		}

		migrationFile, err := os.OpenFile(
			filepath.Join(configDir, "MIGRATIONS"),
			os.O_CREATE|os.O_RDWR,
			fs.FileMode(0600),
		)
		if err != nil {
			panic(err)
		}

		_, err = migrationFile.Write([]byte{0x00, 0x00, 0x01})
		if err != nil {
			panic(err)
		}

		err = migrationFile.Close()
		if err != nil {
			panic(err)
		}
	}
}

func printPeerID(p2pConfig *config.P2PConfig) {
	peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

	fmt.Println("Peer ID: " + id.String())
}

func printLogo() {
	fmt.Println("                                   %#########")
	fmt.Println("                          #############################")
	fmt.Println("                    ########################################&")
	fmt.Println("                 ###############################################")
	fmt.Println("             &#####################%        %######################")
	fmt.Println("           #################                         #################")
	fmt.Println("         ###############                                 ###############")
	fmt.Println("       #############                                        ##############")
	fmt.Println("     #############                                             ############&")
	fmt.Println("    ############                                                 ############")
	fmt.Println("   ###########                     ##########                     &###########")
	fmt.Println("  ###########                    ##############                     ###########")
	fmt.Println(" ###########                     ##############                      ##########&")
	fmt.Println(" ##########                      ##############                       ##########")
	fmt.Println("%##########                        ##########                         ##########")
	fmt.Println("##########                                                            ##########")
	fmt.Println("##########                                                            &#########")
	fmt.Println("##########                    #######      #######                    ##########")
	fmt.Println("%#########                 &#########################                 ##########")
	fmt.Println(" ##########              ##############% ##############              &##########")
	fmt.Println(" '         '          &##############      ###############           ##########")
	fmt.Println("  '         '       ###############           ##############%       ###########")
	fmt.Println("   '         '.       ##########                ###############       ########")
	fmt.Println("    '.         .         #####                     ##############%       ####")
	fmt.Println("      '         '.                                   ###############")
	fmt.Println("       '.         '..                                   ##############%")
	fmt.Println("         '.          '-.                                  ###############")
	fmt.Println("           '-.          ''-..                      ..        ##############%")
	fmt.Println("              '-.            ''---............----'  '.        ###############")
	fmt.Println("                 '-..                                  '.        ############")
	fmt.Println("                     ''-..                             ..'         ########")
	fmt.Println("                          ''---..              ...---''               ##")
	fmt.Println("                                 ''----------''")
}

func printVersion() {
	fmt.Println(" ")
	fmt.Println("                       Quilibrium Node - v1.4.0 – Sunset")
}
