//go:build !js && !wasm

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var (
	configDirectory = flag.String(
		"config",
		filepath.Join(".", ".config"),
		"the configuration directory",
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
	network = flag.Uint(
		"network",
		0,
		"sets the active network for the node (mainnet = 0, primary testnet = 1)",
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

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *peerId {
		config, err := config.LoadConfig(*configDirectory, "")
		if err != nil {
			panic(err)
		}

		printPeerID(config.P2P)
		return
	}

	printLogo()
	printVersion()
	fmt.Println(" ")

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

	node, err := app.NewNode(nodeConfig)
	if err != nil {
		panic(err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		node.Start()
	}()

	<-done
	node.Stop()
}

func getPeerID(p2pConfig *config.P2PConfig) peer.ID {
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

	return id
}

func printPeerID(p2pConfig *config.P2PConfig) {
	id := getPeerID(p2pConfig)

	fmt.Println("Peer ID: " + id.String())
}

func printLogo() {
	fmt.Println("████████████████████████████████████████████████████████████████████████████████")
	fmt.Println("████████████████████████████████████████████████████████████████████████████████")
	fmt.Println("██████████████████████████████                    ██████████████████████████████")
	fmt.Println("█████████████████████████                              █████████████████████████")
	fmt.Println("█████████████████████                                      █████████████████████")
	fmt.Println("██████████████████                                            ██████████████████")
	fmt.Println("████████████████                     ██████                     ████████████████")
	fmt.Println("██████████████                ████████████████████                ██████████████")
	fmt.Println("█████████████             ████████████████████████████              ████████████")
	fmt.Println("███████████            ██████████████████████████████████            ███████████")
	fmt.Println("██████████           ██████████████████████████████████████           ██████████")
	fmt.Println("█████████          ██████████████████████████████████████████          █████████")
	fmt.Println("████████          ████████████████████████████████████████████          ████████")
	fmt.Println("███████          ████████████████████      ████████████████████          ███████")
	fmt.Println("██████          ███████████████████          ███████████████████          ██████")
	fmt.Println("█████          ███████████████████            ███████████████████          █████")
	fmt.Println("█████         ████████████████████            ████████████████████         █████")
	fmt.Println("████         █████████████████████            █████████████████████         ████")
	fmt.Println("████         ██████████████████████          ██████████████████████         ████")
	fmt.Println("████        █████████████████████████      █████████████████████████        ████")
	fmt.Println("████        ████████████████████████████████████████████████████████        ████")
	fmt.Println("████        ████████████████████████████████████████████████████████        ████")
	fmt.Println("████        ████████████████████  ████████████  ████████████████████        ████")
	fmt.Println("████        ██████████████████                   ███████████████████        ████")
	fmt.Println("████         ████████████████                      ████████████████         ████")
	fmt.Println("████         ██████████████            ██            ██████████████         ████")
	fmt.Println("█████        ████████████            ██████            ████████████        █████")
	fmt.Println("█████         █████████            ██████████            █████████         █████")
	fmt.Println("██████         ███████           █████████████             ███████        ██████")
	fmt.Println("██████          ████████       █████████████████            ████████      ██████")
	fmt.Println("███████          █████████   █████████████████████            ████████   ███████")
	fmt.Println("████████           █████████████████████████████████            ████████████████")
	fmt.Println("█████████           ██████████████████████████████████            ██████████████")
	fmt.Println("██████████            ██████████████████████████████████           █████████████")
	fmt.Println("████████████             ████████████████████████████████            ███████████")
	fmt.Println("█████████████               ███████████████████████████████            █████████")
	fmt.Println("███████████████                 ████████████████    █████████            ███████")
	fmt.Println("█████████████████                                     █████████            █████")
	fmt.Println("████████████████████                                    █████████         ██████")
	fmt.Println("███████████████████████                                  ██████████     ████████")
	fmt.Println("███████████████████████████                          ███████████████  ██████████")
	fmt.Println("█████████████████████████████████              █████████████████████████████████")
	fmt.Println("████████████████████████████████████████████████████████████████████████████████")
	fmt.Println("████████████████████████████████████████████████████████████████████████████████")
}

func printVersion() {
	patch := config.GetPatchNumber()
	patchString := ""
	if patch != 0x00 {
		patchString = fmt.Sprintf("-p%d", patch)
	}
	fmt.Println(" ")
	fmt.Println("                Quilibrium Node - v" + config.GetVersionString() + patchString + " – Dusk - Bootstrap Node")
}
