package cparser

import (
	"errors"
	"slices"
	"strings"

	"github.com/itaispiegel/infosec-workshop/user/pkg/utils"
)

const (
	directivePrefix = "#"
)

// Types of preprocessor directives.
// The implemented preprocessor only checks that each directive's type is valid.
// It doesn't check the directive's arguments.
var directiveTypes = []string{
	"assert",
	"define",
	"elif",
	"else",
	"endif",
	"error",
	"if",
	"ifdef",
	"ifndef",
	"include",
	"line",
	"pragma",
	"undef",
	"warning",
}

// Returned when an unsupported directive is used.
var ErrPreprocessorFailed = errors.New("preprocessing failed")

// Splits the given input into lines, normalizing line endings to LF.
func SplitLines(input string) []string {
	normalized := strings.ReplaceAll(input, utils.CRLF, utils.LF)
	return strings.Split(normalized, utils.LF)
}

// Runs the preprocessor on the given input and returns the file with the preprocessor directives removed.
// If the preprocessor fails, an error is returned.
// The preprocessor can fail if an invalid directive is used.
func RunPreprocessor(input string) (string, error) {
	lines := SplitLines(input)
	preprocessedLines := make([]string, 0)
	joinedLines := joinLines(lines)

	for _, line := range joinedLines {
		if strings.HasPrefix(line, directivePrefix) {
			if !validatePreprocessorDirective(line) {
				return "", ErrPreprocessorFailed
			}
		} else {
			preprocessedLines = append(preprocessedLines, line)
		}
	}
	return strings.Join(preprocessedLines, "\n"), nil
}

// Joins the lines that end with a backslash with the next line.
func joinLines(lines []string) []string {
	joinedLines := make([]string, 0)
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t")
		lineWithoutBackslash := strings.TrimSuffix(line, "\\")
		if strings.HasSuffix(line, "\\") && i+1 < len(lines) {
			lines[i+1] = lineWithoutBackslash + lines[i+1]
		} else {
			joinedLines = append(joinedLines, lineWithoutBackslash)
		}
	}
	return joinedLines
}

// Returns whether the preprocessor directive is valid.
func validatePreprocessorDirective(directive string) bool {
	directiveWithoutPrefix := strings.TrimSpace(strings.TrimLeft(directive, directivePrefix))
	spaceIndex := strings.Index(directiveWithoutPrefix, " ")
	var directiveType string
	if spaceIndex == -1 {
		directiveType = directiveWithoutPrefix // In this case the directive has only one argument
	} else {
		directiveType = directiveWithoutPrefix[:spaceIndex]
	}
	return slices.Contains(directiveTypes, directiveType)
}
