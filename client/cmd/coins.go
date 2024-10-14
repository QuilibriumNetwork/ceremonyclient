package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var coinsCmd = &cobra.Command{
	Use:   "coins",
	Short: "Lists all coins under control of the managing account",
	Run: func(cmd *cobra.Command, args []string) {
		conn, err := GetGRPCClient()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)
		peerId := GetPeerIDFromConfig(NodeConfig)
		addr, err := poseidon.HashBytes([]byte(peerId))
		if err != nil {
			panic(err)
		}

		addrBytes := addr.FillBytes(make([]byte, 32))
		resp, err := client.GetTokensByAccount(
			context.Background(),
			&protobufs.GetTokensByAccountRequest{
				Address: addrBytes,
			},
		)
		if err != nil {
			panic(err)
		}

		if len(resp.Coins) != len(resp.FrameNumbers) {
			panic("invalid response from RPC")
		}

		for i, coin := range resp.Coins {
			amount := new(big.Int).SetBytes(coin.Amount)
			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			r := new(big.Rat).SetFrac(amount, conversionFactor)
			addr, err := token.GetAddressOfCoin(coin, resp.FrameNumbers[i])
			if err != nil {
				panic(err)
			}
			fmt.Println(r.FloatString(12), "QUIL (Coin 0x", hex.EncodeToString(addr), ")")
		}
	},
}

func init() {
	tokenCmd.AddCommand(coinsCmd)
}
