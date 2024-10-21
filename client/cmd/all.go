package cmd

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"

	gotime "time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Mints all pre-2.0 rewards",

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			fmt.Println("command has no arguments")
			os.Exit(1)
		}

		conn, err := GetGRPCClient()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		if !LightNode {
			fmt.Println(
				"mint all cannot be run unless node is not running. ensure your node " +
					"is not running and your config.yml has grpc disabled",
			)
			os.Exit(1)
		}

		client := protobufs.NewNodeServiceClient(conn)

		db := store.NewPebbleDB(NodeConfig.DB)
		logger, _ := zap.NewProduction()
		dataProofStore := store.NewPebbleDataProofStore(db, logger)
		peerId := GetPeerIDFromConfig(NodeConfig)
		privKey, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		pub, err := privKey.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		increment, _, _, err := dataProofStore.GetLatestDataTimeProof(
			[]byte(peerId),
		)

		addr, err := poseidon.HashBytes([]byte(peerId))
		if err != nil {
			panic(err)
		}

		if err != nil {
			panic(err)
		}

		resp, err := client.GetPreCoinProofsByAccount(
			context.Background(),
			&protobufs.GetPreCoinProofsByAccountRequest{
				Address: addr.FillBytes(make([]byte, 32)),
			},
		)
		if err != nil {
			panic(err)
		}

		resume := make([]byte, 32)
		for _, pr := range resp.Proofs {
			if pr.IndexProof != nil {
				resume, err = token.GetAddressOfPreCoinProof(pr)
				if err != nil {
					panic(err)
				}
				increment = pr.Difficulty - 1
			}
		}

		proofs := [][]byte{
			[]byte("pre-dusk"),
			resume,
		}

		batchCount := 0
		for i := increment; i >= 0; i-- {
			_, parallelism, input, output, err := dataProofStore.GetDataTimeProof(
				[]byte(peerId),
				uint32(i),
			)
			if err == nil {
				p := []byte{}
				p = binary.BigEndian.AppendUint32(p, i)
				p = binary.BigEndian.AppendUint32(p, parallelism)
				p = binary.BigEndian.AppendUint64(p, uint64(len(input)))
				p = append(p, input...)
				p = binary.BigEndian.AppendUint64(p, uint64(len(output)))
				p = append(p, output...)

				proofs = append(proofs, p)
			} else {
				panic(err)
			}

			batchCount++
			if batchCount == 10 || i == 0 {
				payload := []byte("mint")
				for _, i := range proofs {
					payload = append(payload, i...)
				}
				sig, err := privKey.Sign(payload)
				if err != nil {
					panic(err)
				}

				_, err = client.SendMessage(
					context.Background(),
					&protobufs.TokenRequest{
						Request: &protobufs.TokenRequest_Mint{
							Mint: &protobufs.MintCoinRequest{
								Proofs: proofs,
								Signature: &protobufs.Ed448Signature{
									PublicKey: &protobufs.Ed448PublicKey{
										KeyValue: pub,
									},
									Signature: sig,
								},
							},
						},
					},
				)
				if err != nil {
					panic(err)
				}

				gotime.Sleep(20 * gotime.Second)

				resp, err := client.GetPreCoinProofsByAccount(
					context.Background(),
					&protobufs.GetPreCoinProofsByAccountRequest{
						Address: addr.FillBytes(make([]byte, 32)),
					},
				)
				if err != nil {
					for _, pr := range resp.Proofs {
						if pr.IndexProof != nil {
							resume, err = token.GetAddressOfPreCoinProof(pr)
							if err != nil {
								panic(err)
							}
						}
					}
				}
				batchCount = 0
				proofs = [][]byte{
					[]byte("pre-dusk"),
					resume,
				}
			}
		}
	},
}

func init() {
	mintCmd.AddCommand(allCmd)
}
