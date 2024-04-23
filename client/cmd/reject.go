package cmd

import (
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"
)

var rejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Rejects the pending transaction",
	Long: `Rejects a pending transfer:
	
	reject <PendingTransaction>
	
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

		fmt.Println("25 QUIL (PendingTransaction 0x27fff099dee515ece193d2af09b164864e4bb60c19eb6719b5bc981f92151009)")
	},
}

func init() {
	tokenCmd.AddCommand(rejectCmd)
}
