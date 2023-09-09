package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
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

	if *dbConsole {
		console, err := app.NewDBConsole(nodeConfig)
		if err != nil {
			panic(err)
		}

		console.Run()
		return
	}

	node, err := app.NewNode(nodeConfig)
	if err != nil {
		panic(err)
	}
	node.Start()

	<-done
	node.Stop()
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
	fmt.Println("                  Quilibrium Node - v1.0.0 – DHT Verification")
}
