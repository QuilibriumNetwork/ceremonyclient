//go:build !js && !wasm

package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pbnjay/memory"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
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
	cpuprofile = flag.String(
		"cpuprofile",
		"",
		"write cpu profile to file",
	)
	memprofile = flag.String(
		"memprofile",
		"",
		"write memory profile after 20m to this file",
	)
	nodeInfo = flag.Bool(
		"node-info",
		false,
		"print node related information",
	)
	debug = flag.Bool(
		"debug",
		false,
		"sets log output to debug (verbose)",
	)
	dhtOnly = flag.Bool(
		"dht-only",
		false,
		"sets a node to run strictly as a dht bootstrap peer (not full node)",
	)
	network = flag.Uint(
		"network",
		0,
		"sets the active network for the node (mainnet = 0, primary testnet = 1)",
	)
	signatureCheck = flag.Bool(
		"signature-check",
		true,
		"enables or disables signature validation (default true)",
	)
)

var signatories = []string{
	"b1214da7f355f5a9edb7bcc23d403bdf789f070cca10db2b4cadc22f2d837afb650944853e35d5f42ef3c4105b802b144b4077d5d3253e4100",
	"de4cfe7083104bfe32f0d4082fa0200464d8b10804a811653eedda376efcad64dd222f0f0ceb0b8ae58abe830d7a7e3f3b2d79d691318daa00",
	"540237a35e124882d6b64e7bb5718273fa338e553f772b77fe90570e45303762b34131bdcb6c0b9f2cf9e393d9c7e0f546eeab0bcbbd881680",
	"fbe4166e37f93f90d2ebf06305315ae11b37e501d09596f8bde11ba9d343034fbca80f252205aa2f582a512a72ad293df371baa582da072900",
	"4160572e493e1bf15c44e055b11bf75230c76c7d2c67b48066770ab03dfd5ed34c97b9a431ec18578c83a0df9250b8362c38068650e8b01400",
	"45170b626884b85d61ae109f2aa9b0e1ecc18b181508431ea6308f3869f2adae49da9799a0a594eaa4ef3ad492518fb1729decd44169d40d00",
	"92cd8ee5362f3ae274a75ab9471024dbc144bff441ed8af7d19750ac512ff51e40e7f7b01e4f96b6345dd58878565948c3eb52c53f250b5080",
	"001a4cbfce5d9aeb7e20665b0d236721b228a32f0baee62ffa77f45b82ecaf577e8a38b7ef91fcf7d2d2d2b504f085461398d30b24abb1d700",
	"65b835071731c6e785bb2d107c7d85d8a537d79c435c3f42bb2f87027f93f858d7b37c598cef267a5db46e345f7a6f81969b465686657d1e00",
	"4507626f7164e7d8c304c07ff8d2e23c113fe108b221d2e60672f4d07750345815e2b4b3cc3df4d3466bf2f669c35c3172e06511270612ab00",
	"4fb2537345e46be3d5f96340c1441007501702dd5bfaf6dbf6943bbefceca8fb2b94ec0a8a1a2f49850fbe1d10244889a4f40abfa9e0c9e000",
	"57be2861faf0fffcbfd122c85c77010dce8f213030905781b85b6f345d912c7b5ace17797d9810899dfb8d13e7c8369595740725ab3dd5bd00",
	"61628beef8f6964466fd078d6a2b90a397ab0777a14b9728227fd19f36752f9451b1a8d780740a0b9a8ce3df5f89ca7b9ff17de9274a270980",
	"5547afc71b02821e2f5bfdd30fbe1374c3853898deff20a1b5cc729b8e81670fbbb9d1e917f85d153ea4b26bbf6f9c546dc1b64b9916608d80",
	"81d63a45f068629f568de812f18be5807bfe828a830097f09cf02330d6acd35e3607401df3fda08b03b68ea6e68afd506b23506b11e87a0f80",
	"6e2872f73c4868c4286bef7bfe2f5479a41c42f4e07505efa4883c7950c740252e0eea78eef10c584b19b1dcda01f7767d3135d07c33244100",
	"a114b061f8d35e3f3497c8c43d83ba6b4af67aa7b39b743b1b0a35f2d66110b5051dd3d86f69b57122a35b64e624b8180bee63b6152fce4280",
}

func main() {
	flag.Parse()

	if *signatureCheck {
		if runtime.GOOS == "windows" {
			fmt.Println("Signature check not available for windows yet, skipping...")
		} else {
			ex, err := os.Executable()
			if err != nil {
				panic(err)
			}

			b, err := os.ReadFile(ex)
			if err != nil {
				fmt.Println(
					"Error encountered during signature check – are you running this " +
						"from source? (use --signature-check=false)",
				)
				panic(err)
			}

			checksum := sha3.Sum256(b)
			digest, err := os.ReadFile(ex + ".dgst")
			if err != nil {
				fmt.Println("Digest file not found")
				os.Exit(1)
			}

			parts := strings.Split(string(digest), " ")
			if len(parts) != 2 {
				fmt.Println("Invalid digest file format")
				os.Exit(1)
			}

			digestBytes, err := hex.DecodeString(parts[1][:64])
			if err != nil {
				fmt.Println("Invalid digest file format")
				os.Exit(1)
			}

			if !bytes.Equal(checksum[:], digestBytes) {
				fmt.Println("Invalid digest for node")
				os.Exit(1)
			}

			count := 0

			for i := 1; i <= len(signatories); i++ {
				signatureFile := fmt.Sprintf(ex+".dgst.sig.%d", i)
				sig, err := os.ReadFile(signatureFile)
				if err != nil {
					continue
				}

				pubkey, _ := hex.DecodeString(signatories[i-1])
				if !ed448.Verify(pubkey, digest, sig, "") {
					fmt.Printf("Failed signature check for signatory #%d\n", i)
					os.Exit(1)
				}
				count++
			}

			if count < len(signatories)/2 {
				fmt.Printf("Quorum on signatures not met")
				os.Exit(1)
			}

			fmt.Println("Signature check passed")
		}
	}

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

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *balance {
		config, err := config.LoadConfig(*configDirectory, "")
		if err != nil {
			panic(err)
		}

		printBalance(config)

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

	if *nodeInfo {
		config, err := config.LoadConfig(*configDirectory, "")
		if err != nil {
			panic(err)
		}

		printNodeInfo(config)
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

	if *network != 0 {
		if nodeConfig.P2P.BootstrapPeers[0] == config.BootstrapPeers[0] {
			fmt.Println(
				"Node has specified to run outside of mainnet but is still " +
					"using default bootstrap list. This will fail. Exiting.",
			)
			os.Exit(1)
		}

		nodeConfig.Engine.GenesisSeed = fmt.Sprintf(
			"%02x%s",
			byte(*network),
			nodeConfig.Engine.GenesisSeed,
		)
		nodeConfig.P2P.Network = uint8(*network)
		fmt.Println(
			"Node is operating outside of mainnet – be sure you intended to do this.",
		)
	}

	clearIfTestData(*configDirectory, nodeConfig)

	if *dbConsole {
		console, err := app.NewDBConsole(nodeConfig)
		if err != nil {
			panic(err)
		}

		console.Run()
		return
	}

	if *dhtOnly {
		dht, err := app.NewDHTNode(nodeConfig)
		if err != nil {
			panic(err)
		}

		go func() {
			dht.Start()
		}()

		<-done
		dht.Stop()
		return
	}

	fmt.Println("Loading ceremony state and starting node...")
	kzg.Init()

	report := RunSelfTestIfNeeded(*configDirectory, nodeConfig)

	var node *app.Node
	if *debug {
		node, err = app.NewDebugNode(nodeConfig, report)
	} else {
		node, err = app.NewNode(nodeConfig, report)
	}
	if err != nil {
		panic(err)
	}

	repair(*configDirectory, node)

	if nodeConfig.ListenGRPCMultiaddr != "" {
		srv, err := rpc.NewRPCServer(
			nodeConfig.ListenGRPCMultiaddr,
			nodeConfig.ListenRestMultiaddr,
			node.GetLogger(),
			node.GetClockStore(),
			node.GetKeyManager(),
			node.GetPubSub(),
			node.GetMasterClock(),
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

// Reintroduce at a later date
func RunCompaction(clockStore *store.PebbleClockStore) {
	intrinsicFilter := append(
		p2p.GetBloomFilter(application.CEREMONY_ADDRESS, 256, 3),
		p2p.GetBloomFilterIndices(application.CEREMONY_ADDRESS, 65536, 24)...,
	)
	fmt.Println("running compaction")

	if err := clockStore.Compact(
		intrinsicFilter,
	); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fmt.Println("missing compaction data, skipping for now", zap.Error(err))
		} else {
			panic(err)
		}
	}
	fmt.Println("compaction complete")
}

func RunSelfTestIfNeeded(
	configDir string,
	nodeConfig *config.Config,
) *protobufs.SelfTestReport {
	logger, _ := zap.NewProduction()

	cores := runtime.GOMAXPROCS(0)
	memory := memory.TotalMemory()
	d, err := os.Stat(filepath.Join(configDir, "store"))
	if d == nil {
		err := os.Mkdir(filepath.Join(configDir, "store"), 0755)
		if err != nil {
			panic(err)
		}
	}

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

func repair(configDir string, node *app.Node) {
	_, err := os.Stat(filepath.Join(configDir, "REPAIR"))
	if os.IsNotExist(err) {
		node.RunRepair()

		repairFile, err := os.OpenFile(
			filepath.Join(configDir, "REPAIR"),
			os.O_CREATE|os.O_RDWR,
			fs.FileMode(0600),
		)
		if err != nil {
			panic(err)
		}

		_, err = repairFile.Write([]byte{0x00, 0x00, 0x01})
		if err != nil {
			panic(err)
		}

		err = repairFile.Close()
		if err != nil {
			panic(err)
		}
	}
}

func printBalance(config *config.Config) {
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

func printNodeInfo(cfg *config.Config) {
	if cfg.ListenGRPCMultiaddr == "" {
		_, _ = fmt.Fprintf(os.Stderr, "gRPC Not Enabled, Please Configure\n")
		os.Exit(1)
	}

	printPeerID(cfg.P2P)

	conn, err := app.ConnectToNode(cfg)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)

	nodeInfo, err := app.FetchNodeInfo(client)
	if err != nil {
		panic(err)
	}

	fmt.Println("Version: " + config.FormatVersion(nodeInfo.Version))
	fmt.Println("Max Frame: " + strconv.FormatUint(nodeInfo.GetMaxFrame(), 10))
	fmt.Println("Peer Score: " + strconv.FormatUint(nodeInfo.GetPeerScore(), 10))
	printBalance(cfg)
}

func printLogo() {
	fmt.Println("                                   ..-------..")
	fmt.Println("                          ..---''''           ''''---..")
	fmt.Println("                    .---''                             ''---.")
	fmt.Println("                 .-'                                         '-.")
	fmt.Println("             ..-'            ..--'''''''''''%######################")
	fmt.Println("           .'           .--''                         #################")
	fmt.Println("        .''         ..-'                                 ###############")
	fmt.Println("       '           '                                        ##############")
	fmt.Println("     ''         .''                                             ############&")
	fmt.Println("    '         ''                                                 ############")
	fmt.Println("   '         '                     ##########                     &###########")
	fmt.Println("  '         '                    ##############                     ###########")
	fmt.Println(" '         '                     ##############                      ##########&")
	fmt.Println(" '        '                      ##############                       ##########")
	fmt.Println("'        '                         ##########                         ##########")
	fmt.Println("'        '                                                            ##########")
	fmt.Println("'        '                                                            &#########")
	fmt.Println("'        '                    #######      #######                    ##########")
	fmt.Println("'        '                 &#########################                 ##########")
	fmt.Println(" '        '              ##############% ##############              &##########")
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
	patch := config.GetPatchNumber()
	patchString := ""
	if patch != 0x00 {
		patchString = fmt.Sprintf("-p%d", patch)
	}
	fmt.Println(" ")
	fmt.Println("                       Quilibrium Node - v" + config.GetVersionString() + patchString + " – Nebula")
}
