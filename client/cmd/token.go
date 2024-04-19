package cmd

import (
	"github.com/spf13/cobra"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Performs a token operation",
}

func init() {
	rootCmd.AddCommand(tokenCmd)
}
