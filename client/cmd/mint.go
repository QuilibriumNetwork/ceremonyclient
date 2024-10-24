package cmd

import (
	"context"
	"encoding/binary"

	gotime "time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var mintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Performs a mint operation",

	Run: func(cmd *cobra.Command, args []string) {
		conn, err := GetGRPCClient()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)

		db := store.NewPebbleDB(NodeConfig.DB)
		logger, _ := zap.NewProduction()
		dataProofStore := store.NewPebbleDataProofStore(db, logger)
		peerId := GetPeerIDFromConfig(NodeConfig)
		key, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		pub, err := key.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		inc, _, _, err := dataProofStore.GetLatestDataTimeProof([]byte(peerId))

		if err != nil {
			panic(err)
		}

		for j := int(inc); j >= 0; j-- {
			_, par, input, output, err := dataProofStore.GetDataTimeProof([]byte(peerId), uint32(j))
			if err == nil {
				p := []byte{}
				p = binary.BigEndian.AppendUint32(p, uint32(j))
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

				sig, err := key.Sign(payload)
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
			}
			gotime.Sleep(10 * gotime.Second)
		}
	},
}

func init() {
	tokenCmd.AddCommand(mintCmd)
}
