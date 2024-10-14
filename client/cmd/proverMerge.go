package cmd

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var proverConfigMergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merges config data for prover seniority",
	Long: `Merges config data for prover seniority:
	
	merge <Primary Config Path> [<Additional Config Paths>...]

	Use with --dry-run to evaluate seniority score, this may take a while...
	`,
	Run: func(c *cobra.Command, args []string) {
		if len(args) <= 1 {
			fmt.Println("missing configs")
			os.Exit(1)
		}

		primaryConfig, err := config.LoadConfig(args[0], "", true)
		if err != nil {
			fmt.Printf("invalid config directory: %s\n", args[0])
			os.Exit(1)
		}

		otherPaths := []string{}
		peerIds := []string{GetPeerIDFromConfig(primaryConfig).String()}
		for _, p := range args[1:] {
			if !path.IsAbs(p) {
				fmt.Printf("%s is not an absolute path\n", p)
			}
			cfg, err := config.LoadConfig(p, "", true)
			if err != nil {
				fmt.Printf("invalid config directory: %s\n", p)
				os.Exit(1)
			}

			peerId := GetPeerIDFromConfig(cfg).String()
			peerIds = append(peerIds, peerId)
			otherPaths = append(otherPaths, p)
		}

		if DryRun {
			bridged := []*BridgedPeerJson{}
			firstRetro := []*FirstRetroJson{}
			secondRetro := []*SecondRetroJson{}
			thirdRetro := []*ThirdRetroJson{}
			fourthRetro := []*FourthRetroJson{}

			err = json.Unmarshal(bridgedPeersJsonBinary, &bridged)
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

			bridgeTotal := decimal.Zero
			for _, b := range bridged {
				amt, err := decimal.NewFromString(b.Amount)
				if err != nil {
					panic(err)
				}
				bridgeTotal = bridgeTotal.Add(amt)
				bridgedAddrs[b.Identifier] = struct{}{}
			}

			highestFirst := uint64(0)
			highestSecond := uint64(0)
			highestThird := uint64(0)
			highestFourth := uint64(0)

			for _, f := range firstRetro {
				found := false
				for _, p := range peerIds {
					if p != f.PeerId {
						continue
					}
					found = true
				}
				if !found {
					continue
				}
				// these don't have decimals so we can shortcut
				max := 157208
				actual, err := strconv.Atoi(f.Reward)
				if err != nil {
					panic(err)
				}

				s := uint64(10 * 6 * 60 * 24 * 92 / (max / actual))
				if s > uint64(highestFirst) {
					highestFirst = s
				}
			}

			for _, f := range secondRetro {
				found := false
				for _, p := range peerIds {
					if p != f.PeerId {
						continue
					}
					found = true
				}
				if !found {
					continue
				}

				amt := uint64(0)
				if f.JanPresence {
					amt += (10 * 6 * 60 * 24 * 31)
				}

				if f.FebPresence {
					amt += (10 * 6 * 60 * 24 * 29)
				}

				if f.MarPresence {
					amt += (10 * 6 * 60 * 24 * 31)
				}

				if f.AprPresence {
					amt += (10 * 6 * 60 * 24 * 30)
				}

				if f.MayPresence {
					amt += (10 * 6 * 60 * 24 * 31)
				}

				if amt > uint64(highestSecond) {
					highestSecond = amt
				}
			}

			for _, f := range thirdRetro {
				found := false
				for _, p := range peerIds {
					if p != f.PeerId {
						continue
					}
					found = true
				}
				if !found {
					continue
				}

				s := uint64(10 * 6 * 60 * 24 * 30)
				if s > uint64(highestThird) {
					highestThird = s
				}
			}

			for _, f := range fourthRetro {
				found := false
				for _, p := range peerIds {
					if p != f.PeerId {
						continue
					}
					found = true
				}
				if !found {
					continue
				}

				s := uint64(10 * 6 * 60 * 24 * 31)
				if s > uint64(highestFourth) {
					highestFourth = s
				}
			}

			fmt.Printf("Effective seniority score: %d\n", highestFirst+highestSecond+highestThird+highestFourth)
		} else {
			for _, p := range args[1:] {
				primaryConfig.Engine.MultisigProverEnrollmentPaths = append(
					primaryConfig.Engine.MultisigProverEnrollmentPaths,
					p,
				)
			}
			err := config.SaveConfig(args[0], primaryConfig)
			if err != nil {
				panic(err)
			}
		}
	},
}

func GetPrivKeyFromConfig(cfg *config.Config) (crypto.PrivKey, error) {
	peerPrivKey, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	return privKey, err
}

func GetPeerIDFromConfig(cfg *config.Config) peer.ID {
	peerPrivKey, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
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

//go:embed first_retro.json
var firstRetroJsonBinary []byte

//go:embed second_retro.json
var secondRetroJsonBinary []byte

//go:embed third_retro.json
var thirdRetroJsonBinary []byte

//go:embed fourth_retro.json
var fourthRetroJsonBinary []byte

func init() {
	proverCmd.AddCommand(proverConfigMergeCmd)
}
