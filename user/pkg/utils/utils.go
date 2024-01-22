package utils

import "strings"

const (
	CRLF = "\r\n"
	LF   = "\n"
)

func SplitLines(text string) []string {
	normalized := strings.Replace(text, CRLF, LF, -1)
	return strings.Split(normalized, LF)
}
