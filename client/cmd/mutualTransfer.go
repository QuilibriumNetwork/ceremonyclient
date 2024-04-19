package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var mutualTransferCmd = &cobra.Command{
	Use:   "mutual-transfer",
	Short: "Initiates a mutual transfer",
	Long: `Initiates a mutual transfer:
	
	mutual-transfer <Rendezvous> (<Amount>|<OfCoin>)
	
	Rendezvous - the rendezvous point to connect to the recipient
	Amount – the amount to send, splitting/merging and sending as needed
	OfCoin – the address of the coin to send in whole

	Either Amount or OfCoin must be specified
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 2 {
			fmt.Println("invalid command")
			os.Exit(1)
		}

		fmt.Printf("Confirming rendezvous... ")
		time.Sleep(500 * time.Millisecond)
		fmt.Println("OK")
		fmt.Println("50 QUIL (Coin [private])")
	},
}

func init() {
	tokenCmd.AddCommand(mutualTransferCmd)
}
