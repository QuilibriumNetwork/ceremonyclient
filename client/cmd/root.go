package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var configDirectory string
var simulateFail bool

var rootCmd = &cobra.Command{
	Use:   "qclient",
	Short: "Quilibrium RPC Client",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(
		&configDirectory,
		"config",
		".config/",
		"config directory (default is .config/)",
	)
}
