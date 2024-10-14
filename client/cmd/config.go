package cmd

import "github.com/spf13/cobra"

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Performs a configuration operation",
}

func init() {
	rootCmd.AddCommand(configCmd)
}
