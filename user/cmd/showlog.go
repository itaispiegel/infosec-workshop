package cmd

import (
	"fmt"

	"github.com/itaispiegel/infosec-workshop/user/pkg/logs"
	"github.com/spf13/cobra"
)

var showLogCmd = &cobra.Command{
	Use:   "show_log",
	Short: "Show the firewall log",
	RunE:  executeShowLog,
}

func executeShowLog(cmd *cobra.Command, args []string) error {
	logs, err := logs.ReadFromDevice()
	if err != nil {
		return err
	}

	fmt.Println(logs.String())
	return nil
}

func init() {
	RootCmd.AddCommand(showLogCmd)
}
