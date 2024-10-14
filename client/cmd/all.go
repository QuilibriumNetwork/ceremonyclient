package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Mints all available token rewards",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("command not yet available")
	},
}

func init() {
	mintCmd.AddCommand(allCmd)
}
