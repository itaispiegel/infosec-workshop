package cmd

import (
	"fmt"
	"os"

	"github.com/itaispiegel/infosec-workshop/user/cparser"
	"github.com/spf13/cobra"
)

var cparserCmd = &cobra.Command{
	Use: "cparser",
	Long: `Run the C parser on a given source file.
If the parser fails, the error will be printed to the console, and the program will exit with a non-zero exit code.`,
	Args: cobra.ExactArgs(1),
	RunE: executeCParser,
}

func executeCParser(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	parserResult := cparser.Parse(string(fileContent))
	if !parserResult.Success {
		fmt.Printf("Failed parsing: %s\n", parserResult.Error)
		os.Exit(1)
	}
	return nil
}

func init() {
	RootCmd.AddCommand(cparserCmd)
}
