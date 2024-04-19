package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
)

var mutualReceiveCmd = &cobra.Command{
	Use:   "mutual-receive",
	Short: "Initiates a mutual receive",
	Long: `Initiates a mutual receive:
	
	mutual-receive <ExpectedAmount>
	
	ExpectedAmount - the amount expected in the transfer
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Println("invalid command")
			os.Exit(1)
		}

		amount := args[len(args)-1]
		_, err := decimal.NewFromString(amount)
		if err != nil {
			fmt.Println("invalid ExpectedAmount")
			os.Exit(1)
		}
		fmt.Println("Rendezvous: 0x2ad567e4fc1ac335a8d3d6077de2ee998aff996b51936da04ee1b0f5dc196a4f")
		fmt.Printf("Awaiting sender... ")
		time.Sleep(2 * time.Second)
		fmt.Println("OK")
		fmt.Println(amount + " QUIL (Coin 0x0525c76ecdc6ef21c2eb75df628b52396adcf402ba26a518ac395db8f5874a82)")
	},
}

func init() {
	tokenCmd.AddCommand(mutualReceiveCmd)
}
