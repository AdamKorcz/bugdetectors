package io

import (
	"bytes"
	"fmt"
	"testing"
)

func TestReadAll(t *testing.T) {
	_, _ = ReadAll(bytes.NewReader([]byte{0x40, 0x41, 0x42}), "codeSnippet")
}

func TestGetDescription(t *testing.T) {
	returnString := GetDescription("line1.go")
	fmt.Println(returnString)
}
