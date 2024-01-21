package cmd

import (
	"fmt"

	"github.com/itaispiegel/infosec-workshop/user/pkg/rulestable"
	"github.com/spf13/cobra"
)

var showCmd = &cobra.Command{
	Use:   "show_rules",
	Short: "Show the firewall rules",
	RunE:  executeShowRules,
}

func executeShowRules(cmd *cobra.Command, args []string) error {
	table, err := rulestable.ReadRules()
	if err != nil {
		return err
	}

	for _, rule := range table {
		fmt.Println(rule.ToString())
	}

	return nil
}

func init() {
	RootCmd.AddCommand(showCmd)
}
