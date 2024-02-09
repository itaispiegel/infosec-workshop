package cmd

import (
	"github.com/itaispiegel/infosec-workshop/user/pkg/conntrack"
	"github.com/spf13/cobra"
)

var showConnsCmd = &cobra.Command{
	Use:   "show_conns",
	Short: "Shows the open connections table",
	RunE:  executeShowConns,
}

func executeShowConns(cmd *cobra.Command, args []string) error {
	conns, err := conntrack.ReadConnections()
	if err != nil {
		return err
	}

	conns.Table().Print()
	return nil
}

func init() {
	RootCmd.AddCommand(showConnsCmd)
}
