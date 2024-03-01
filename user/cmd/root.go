package cmd

import (
	"os"

	"github.com/itaispiegel/infosec-workshop/user/pkg/module"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "firewall",
	Short: "A simple CLI tool for managing the TAU infosec workshop firewall",
	Long: "A simple CLI tool for managing the TAU infosec workshop firewall " +
		"implemented by Itai Spiegel during the Fall 2024 semester.\n" +
		"In order for the CLI to work, first ensure that the kernel module is loaded.",
	SilenceUsage: true,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

func Execute() {
	if !module.IsLoaded() {
		RootCmd.Println("Error: The firewall kernel module is not loaded.")
		os.Exit(1)
	}

	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
