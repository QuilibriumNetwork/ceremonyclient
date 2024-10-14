package cmd

import (
	"context"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

var balanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Lists the total balance of tokens in the managing account",
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
		info, err := client.GetTokenInfo(
			context.Background(),
			&protobufs.GetTokenInfoRequest{
				Address: addrBytes,
			},
		)
		if err != nil {
			panic(err)
		}

		if info.OwnedTokens == nil {
			panic("invalid response from RPC")
		}
		tokens := new(big.Int).SetBytes(info.OwnedTokens)
		conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
		r := new(big.Rat).SetFrac(tokens, conversionFactor)
		fmt.Println("Total balance:", r.FloatString(12), "QUIL")
	},
}

func init() {
	tokenCmd.AddCommand(balanceCmd)
}
