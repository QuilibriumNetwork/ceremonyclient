package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var balanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Lists the total balance of tokens in the managing account",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("1545.381923 QUIL (Account 0x026a5cf3d486b8e8733060d6ce0060074616f0f925671a0886faef744412dc8a)")
	},
}

func init() {
	tokenCmd.AddCommand(balanceCmd)
}
