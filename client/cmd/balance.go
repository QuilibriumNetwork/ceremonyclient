package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var balanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Lists the total balance of tokens in the managing account",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("1545.381923 QUIL")
	},
}

func init() {
	tokenCmd.AddCommand(balanceCmd)
}
