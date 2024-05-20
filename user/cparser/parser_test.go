package cparser

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// Runs the parser on all tests cases in the testdata directory.
// Assert that the output is equal to the expected parser result.
func TestParser(t *testing.T) {
	testCases := getTestCases(t)
	for _, testName := range testCases {
		t.Run(testName, func(t *testing.T) {
			inputFilePath := path.Join(testDataDir, testName, testInputFileName)
			parserStatusPath := path.Join(testDataDir, testName, testParserResultFileName)

			input, err := os.ReadFile(inputFilePath)
			assert.NoError(t, err)

			expectedParserStatus := CParserResult{}
			parserStatusBytes, err := os.ReadFile(parserStatusPath)
			assert.NoError(t, err)
			err = yaml.Unmarshal(parserStatusBytes, &expectedParserStatus)
			assert.NoError(t, err)

			actualParserStatus := Parse(string(input))
			assert.Equal(t, expectedParserStatus, actualParserStatus, "Test case '%s' failed", testName)
		})
	}
}
