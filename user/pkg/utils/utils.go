package utils

import (
	"strings"
)

const (
	CRLF = "\r\n"
	LF   = "\n"
)

// Splits a string into lines, and returns a slice of the lines.
// The string can be in either CRLF or LF line endings.
// If the string is empty, an empty slice is returned.
func SplitLines(text string) []string {
	normalized := strings.Replace(text, CRLF, LF, -1)
	if res := strings.Split(normalized, LF); len(res) == 1 && res[0] == "" {
		return []string{}
	} else {
		return res
	}
}

// Removes lines from a slice of lines that start with a given prefix.
func RemoveLinesWithPrefix(lines []string, prefix string) []string {
	var res []string
	for _, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			res = append(res, line)
		}
	}
	return res
}

func PanicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
