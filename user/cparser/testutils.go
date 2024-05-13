package cparser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testDataDir              = "testdata"
	testInputFileName        = "input.c"
	testPreprocessedFileName = "preprocessed.c"
	testParserResultFileName = "parser.yml"
)

// Get all test cases in the testdata directory.
// Each test case is a directory with the following files:
// - input.c: The input C code to preprocess.
// - preprocessed.c: The expected preprocessed C code.
// - parser.yml: The expected parser result.
func getTestCases(t *testing.T) []string {
	entries, err := os.ReadDir(testDataDir)
	assert.NoError(t, err)
	testCases := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			testCases = append(testCases, entry.Name())
		}
	}
	return testCases
}
