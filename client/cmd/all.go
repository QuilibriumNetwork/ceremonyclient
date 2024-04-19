package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Mints all available token rewards",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("1520.381923 QUIL (Coin 0x162ad88c319060b4f5ea6dbf9a0c2cd82d3d70dfc22d5fc99ca5371083d68416)")
	},
}

func init() {
	mintCmd.AddCommand(allCmd)
}
