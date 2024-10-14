package cmd

import "github.com/spf13/cobra"

var proverCmd = &cobra.Command{
	Use:   "prover",
	Short: "Performs a configuration operation for given prover info",
}

func init() {
	configCmd.AddCommand(proverCmd)
}
