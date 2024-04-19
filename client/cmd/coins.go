package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var coinsCmd = &cobra.Command{
	Use:   "coins",
	Short: "Lists all coins under control of the managing account",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("25.0 QUIL (Coin 0x1148092cdce78c721835601ef39f9c2cd8b48b7787cbea032dd3913a4106a58d)")
		fmt.Println("1520.381923 QUIL (Coin 0x162ad88c319060b4f5ea6dbf9a0c2cd82d3d70dfc22d5fc99ca5371083d68416)")
	},
}

func init() {
	tokenCmd.AddCommand(coinsCmd)
}
