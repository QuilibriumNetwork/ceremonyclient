//go:build !js && !wasm

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
)

var (
	configDirectory = flag.String(
		"config",
		"./.config/",
		"the configuration directory",
	)
	importPrivKey = flag.String(
		"import-priv-key",
		"",
		"creates a new config using a specific key from the phase one ceremony",
	)
	dbConsole = flag.Bool(
		"db-console",
		false,
		"starts the node in database console mode",
	)
)

func main() {
	flag.Parse()

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

	printLogo()
	printVersion()
	fmt.Println(" ")

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
	qcrypto.Init()

	node, err := app.NewNode(nodeConfig)
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
			fs.FileMode(0700),
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
			fs.FileMode(0700),
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
	fmt.Println("##########&                                                           ##########")
	fmt.Println("##########                                                            &#########")
	fmt.Println("##########&                   #######      #######                    ##########")
	fmt.Println(" ##########                &#########################                 ##########")
	fmt.Println(" ##########              ##############% ##############              &##########")
	fmt.Println(" %##########          &##############      ###############           ##########")
	fmt.Println("  ###########       ###############           ##############%       ###########")
	fmt.Println("   ###########&       ##########                ###############       ########")
	fmt.Println("    ############         #####                     ##############%       ####")
	fmt.Println("      ############                                   ###############")
	fmt.Println("       ##############                                   ##############%")
	fmt.Println("         ###############                                  ###############")
	fmt.Println("           #################&                                ##############%")
	fmt.Println("              #########################&&&#############        ###############")
	fmt.Println("                 ########################################%        ############")
	fmt.Println("                     #######################################        ########")
	fmt.Println("                          #############################                ##")
}

func printVersion() {
	fmt.Println(" ")
	fmt.Println("                         Quilibrium Node - v1.1.6 – Dawn")
}
