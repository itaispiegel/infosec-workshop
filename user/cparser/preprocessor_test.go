package cparser

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreprocessor(t *testing.T) {
	testCases := getTestCases(t)
	for _, testName := range testCases {
		t.Run(testName, func(t *testing.T) {
			inputFilePath := path.Join(testDataDir, testName, testInputFileName)
			preprocessedFilePath := path.Join(testDataDir, testName, testPreprocessedFileName)

			input, err := os.ReadFile(inputFilePath)
			assert.NoError(t, err)
			actual, preprocessError := RunPreprocessor(string(input))
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
