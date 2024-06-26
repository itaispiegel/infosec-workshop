package cparser

//go:generate bison -d parser.y
//go:generate lex parser.l

// #include <stdlib.h>
// #include "parser.tab.h"
import "C"
import (
	"errors"
	"strings"
	"unsafe"
)

var ErrEmptyString = errors.New("empty string")

// CParserResult represents the result of parsing an input string as C code.
// Success is true if the input was successfully parsed, and false otherwise.
// Error contains an error message if Success is false.
type CParserResult struct {
	Success bool   `yaml:"success"`
	Error   string `yaml:"error"`
}

// Parses the input as C code, and returns the result of the parsing.
func Parse(input string) CParserResult {
	trimmedInput := strings.TrimSpace(input)
	if len(trimmedInput) == 0 {
		return CParserResult{Success: false, Error: ErrEmptyString.Error()}
	}
	preprocessed, err := RunPreprocessor(trimmedInput)
	if err != nil {
		return CParserResult{Success: false, Error: err.Error()}
	}
	errorCstr := C.parse(C.CString(preprocessed))
	errorGoStr := C.GoString(errorCstr)
	if errorGoStr == "" {
		return CParserResult{Success: true, Error: ""}
	} else {
		C.free(unsafe.Pointer(errorCstr))
		return CParserResult{Success: false, Error: errorGoStr}
	}
}
