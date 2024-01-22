package cmd

import (
	"os"
	"strings"

	"github.com/itaispiegel/infosec-workshop/user/pkg/rules"
	"github.com/itaispiegel/infosec-workshop/user/pkg/rulestable"
	"github.com/spf13/cobra"
)

var loadCmd = &cobra.Command{
	Use:   "load_rules [rules_file]",
	Short: "Load the firewall rules from a given file",
	Args:  cobra.ExactArgs(1),
	RunE:  executeLoadRules,
}

func executeLoadRules(cmd *cobra.Command, args []string) error {
	rulesFilePath := args[0]
	rulesBytes, err := os.ReadFile(rulesFilePath)
	if err != nil {
		return err
	}

	normalizedRules := strings.Replace(string(rulesBytes), "\r\n", "\n", -1)
	rulesLines := strings.Split(normalizedRules, "\n")
	newRules := make([]rules.Rule, len(rulesLines))
	for i, ruleLine := range rulesLines {
		rule, err := rules.ParseRule(ruleLine)
		if err != nil {
			return err
		}

		newRules[i] = *rule
	}

	return rulestable.SaveRules(newRules)
}

func init() {
	RootCmd.AddCommand(loadCmd)
}
