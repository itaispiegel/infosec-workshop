package cmd

import (
	"github.com/itaispiegel/infosec-workshop/user/pkg/logs"
	"github.com/spf13/cobra"
)

var clearLogCmd = &cobra.Command{
	Use:   "clear_log",
	Short: "Clear the firewall logs table",
	RunE:  executeClearLog,
}

func executeClearLog(cmd *cobra.Command, args []string) error {
	return logs.ClearLogsDevice()
}

func init() {
	RootCmd.AddCommand(clearLogCmd)
}
