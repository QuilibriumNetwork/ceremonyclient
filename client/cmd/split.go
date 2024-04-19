package cmd

import (
	"fmt"
	"math/big"
	"os"

	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
)

var splitCmd = &cobra.Command{
	Use:   "split",
	Short: "Splits a coin into two coins",
	Long: `Splits a coin into two coins:
	
	split <OfCoin> <LeftAmount> <RightAmount>
	
	OfCoin - the address of the coin to split
	LeftAmount - the first half of the split amount
	RightAmount - the second half of the split amount
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 3 {
			fmt.Println("invalid command")
			os.Exit(1)
		}

		_, ok := new(big.Int).SetString(args[0], 0)
		if !ok {
			fmt.Println("invalid OfCoin")
			os.Exit(1)
		}

		leftAmount := args[1]
		_, err := decimal.NewFromString(leftAmount)
		if err != nil {
			fmt.Println("invalid LeftAmount")
			os.Exit(1)
		}

		rightAmount := args[2]
		_, err = decimal.NewFromString(rightAmount)
		if err != nil {
			fmt.Println("invalid RightAmount")
			os.Exit(1)
		}
		fmt.Println(leftAmount + " QUIL (Coin 0x024479f49f03dc53fd702198cd9b548c9e96004e19ef6a4e9c5211a9795ba34d)")
		fmt.Println(rightAmount + " QUIL (Coin 0x0140e01731256793bba03914f3844d645fbece26553acdea8ac4de4d84f91690)")
	},
}

func init() {
	tokenCmd.AddCommand(splitCmd)
}
