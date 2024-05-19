package cmd

import (
	"github.com/itaispiegel/infosec-workshop/user/pkg/fwlogs"
	"github.com/spf13/cobra"
)

var showLogCmd = &cobra.Command{
	Use:    "show_log",
	Short:  "Show the firewall log",
	PreRun: ensureKernelModuleLoaded,
	RunE:   executeShowLog,
}

func executeShowLog(cmd *cobra.Command, args []string) error {
	logs, err := fwlogs.ReadFromDevice()
	if err != nil {
		return err
	}

	logs.Table().Print()
	return nil
}

func init() {
	RootCmd.AddCommand(showLogCmd)
}
