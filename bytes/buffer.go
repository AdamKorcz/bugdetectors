package bytes

import (
	"bytes"
	"reflect"
	"strings"
)

var MaxBufferSize = 1000000

func GetDescription(faultyLine string) string {
	var sb strings.Builder

	sb.WriteString("\n# (This bug detector is currently in beta) \n")
	sb.WriteString("\n We have found an issue \n")
	sb.WriteString("\n# The vulnerable API is: \n\n")
	sb.WriteString(strings.Replace(faultyLine, "NEW_LINE", "\n", -1))
	sb.WriteString("\n")
	return sb.String()
}

func CheckLen(b []byte, codeSnippet string) []byte {
	if len(b) > MaxBufferSize {
		panic(GetDescription(codeSnippet))
	}
	return b
}
