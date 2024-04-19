package cmd

import (
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"
)

var mergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merges two coins",
	Long: `Merges two coins:
	
	merge <LeftCoin> <RightCoin>
	
	LeftCoin - the first coin address
	RightCoin - the second coin address
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 2 {
			fmt.Println("invalid command")
			os.Exit(1)
		}

		_, ok := new(big.Int).SetString(args[0], 0)
		if !ok {
			fmt.Println("invalid LeftCoin")
			os.Exit(1)
		}

		_, ok = new(big.Int).SetString(args[1], 0)
		if !ok {
			fmt.Println("invalid Rightcoin")
			os.Exit(1)
		}

		fmt.Println("1545.381923 QUIL (Coin 0x151f4ae225e20759077e1724e4c5d0feae26c477fd10d728dfea962eec79b83f)")
	},
}

func init() {
	tokenCmd.AddCommand(mergeCmd)
}
