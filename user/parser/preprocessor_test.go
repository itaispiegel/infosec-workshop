package parser

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

const (
	testDataDir = "testdata"
)

func TestPreprocessor(t *testing.T) {
	testCases := getTestCases(t)
	for _, testName := range testCases {
		t.Run(testName, func(t *testing.T) {
			inputFilePath := path.Join(testDataDir, testName, "input.c")
			preprocessedFilePath := path.Join(testDataDir, testName, "preprocessed.c")

			input, err := os.ReadFile(inputFilePath)
			assert.NoError(t, err)
			actual, preprocessError := Preprocess(string(input))
			if _, err := os.Stat(preprocessedFilePath); os.IsNotExist(err) {
				assert.ErrorIs(t, preprocessError, ErrPreprocessorFailed, "Test case '%s' didn't return a preprocessor error", testName)
			} else {
				assert.NoError(t, preprocessError)
				expected, err := os.ReadFile(preprocessedFilePath)
				assert.NoError(t, err)
				assert.Equal(t, string(expected), actual, "Test case '%s' failed", testName)
			}
		})
	}
}

func TestParser(t *testing.T) {
	testCases := getTestCases(t)
	for _, testName := range testCases {
		t.Run(testName, func(t *testing.T) {
			inputFilePath := path.Join(testDataDir, testName, "input.c")
			parserStatusPath := path.Join(testDataDir, testName, "parser.txt")

			input, err := os.ReadFile(inputFilePath)
			assert.NoError(t, err)

			expectedParserStatus := ParserStatus{}
			parserStatusBytes, err := os.ReadFile(parserStatusPath)
			assert.NoError(t, err)
			yaml.Unmarshal(parserStatusBytes, &expectedParserStatus)

			actualParserStatus := Parse(string(input))
			assert.Equal(t, expectedParserStatus, actualParserStatus, "Test case '%s' failed", testName)
		})
	}
}

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
