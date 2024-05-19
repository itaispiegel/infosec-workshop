package cmd

import (
	"github.com/itaispiegel/infosec-workshop/user/pkg/fwlogs"
	"github.com/spf13/cobra"
)

var clearLogCmd = &cobra.Command{
	Use:    "clear_log",
	Short:  "Clear the firewall logs table",
	PreRun: ensureKernelModuleLoaded,
	RunE:   executeClearLog,
}

func executeClearLog(cmd *cobra.Command, args []string) error {
	return fwlogs.ClearLogsDevice()
}

func init() {
	RootCmd.AddCommand(clearLogCmd)
}
