package cmd

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var mergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merges multiple coins",
	Long: `Merges multiple coins:
	
	merge <Coin Addresses>...
	`,
	Run: func(cmd *cobra.Command, args []string) {
		conn, err := GetGRPCClient()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)
		key, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		coinaddrs := []*protobufs.CoinRef{}
		payload := []byte("merge")
		for _, arg := range args {
			coinaddrHex, _ := strings.CutPrefix(arg, "0x")
			coinaddr, err := hex.DecodeString(coinaddrHex)
			if err != nil {
				panic(err)
			}
			coinaddrs = append(coinaddrs, &protobufs.CoinRef{
				Address: coinaddr,
			})
			payload = append(payload, coinaddr...)
		}

		sig, err := key.Sign(payload)
		if err != nil {
			panic(err)
		}

		pub, err := key.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		_, err = client.SendMessage(
			context.Background(),
			&protobufs.TokenRequest{
				Request: &protobufs.TokenRequest_Merge{
					Merge: &protobufs.MergeCoinRequest{
						Coins: coinaddrs,
						Signature: &protobufs.Ed448Signature{
							Signature: sig,
							PublicKey: &protobufs.Ed448PublicKey{
								KeyValue: pub,
							},
						},
					},
				},
			},
		)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	tokenCmd.AddCommand(mergeCmd)
}
