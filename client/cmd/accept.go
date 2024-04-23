package cmd

import (
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"
)

var acceptCmd = &cobra.Command{
	Use:   "accept",
	Short: "Accepts a pending transfer",
	Long: `Accepts a pending transfer:
	
	accept <PendingTransaction>
	
	PendingTransaction - the address of the pending transfer
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Println("invalid command")
			os.Exit(1)
		}

		_, ok := new(big.Int).SetString(args[0], 0)
		if !ok {
			fmt.Println("invalid PendingTransaction")
			os.Exit(1)
		}

		fmt.Println("25 QUIL (Coin 0x2688997f2776ab5993894ed04fcdac05577cf2494ddfedf356ebf8bd3de464ab)")
	},
}

func init() {
	tokenCmd.AddCommand(acceptCmd)
}
