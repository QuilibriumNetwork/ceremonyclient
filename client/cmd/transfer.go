package cmd

import (
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
)

var transferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Creates a pending transfer of coin",
	Long: `Creates a pending transfer of coin:
	
	transfer <ToAccount> [<RefundAccount>] [<Expiry>] (<Amount>|<OfCoin>)
	
	ToAccount – account address, must be specified
	RefundAccount - account address to receive coin if rejected (if omitted, uses sender address)
	Expiry – unix epoch time in seconds where the ToAccount can no longer claim (if omitted, does not expire)
	Amount – the amount to send, splitting/merging and sending as needed
	OfCoin – the address of the coin to send in whole

	Either Amount or OfCoin must be specified
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 || len(args) > 4 {
			fmt.Println("invalid command")
			os.Exit(1)
		}

		_, ok := new(big.Int).SetString(args[0], 0)
		if !ok {
			fmt.Println("invalid ToAccount")
			os.Exit(1)
		}

		refundAccount := "0x23c0f371e9faa7be4ffedd616361e0c9aeb776ae4d7f3a37605ecbfa40a55a90"
		// expiry := int64(9999999999)
		var err error

		if len(args) >= 3 {
			if len(args[len(args)-2]) != 66 {
				_, err = strconv.ParseInt(args[len(args)-2], 10, 0)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			} else {
				refundAccount = args[1]
			}
		}

		if refundAccount[0] != '0' || refundAccount[1] != 'x' {
			_, ok := new(big.Int).SetString(refundAccount, 0)
			if !ok {
				fmt.Println("invalid refund account")
				os.Exit(1)
			}
		}

		ofCoin := ""
		amount := ""
		if len(args[len(args)-1]) == 66 {
			ofCoin = args[len(args)-1]
			_, ok := new(big.Int).SetString(ofCoin, 0)
			if !ok {
				fmt.Println("invalid OfCoin")
				os.Exit(1)
			}
			switch ofCoin {
			case "0x1148092cdce78c721835601ef39f9c2cd8b48b7787cbea032dd3913a4106a58d":
				fmt.Println("25.0 QUIL (Pending Transaction 0x0382e4da0c7c0133a1b53453b05096272b80c1575c6828d0211c4e371f7c81bb)")
			case "0x162ad88c319060b4f5ea6dbf9a0c2cd82d3d70dfc22d5fc99ca5371083d68416":
				fmt.Println("1520.381923 QUIL (Pending Transaction 0x0382e4da0c7c0133a1b53453b05096272b80c1575c6828d0211c4e371f7c81bb)")
			}
		} else {
			amount = args[len(args)-1]
			_, err := decimal.NewFromString(amount)
			if err != nil {
				fmt.Println("invalid Amount")
				os.Exit(1)
			}
			fmt.Println(amount + " QUIL (Pending Transaction 0x0382e4da0c7c0133a1b53453b05096272b80c1575c6828d0211c4e371f7c81bb)")
		}
	},
}

func init() {
	tokenCmd.AddCommand(transferCmd)
}
