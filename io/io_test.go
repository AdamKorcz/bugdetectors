package io

import (
	"bytes"
	"testing"
)

func TestReadAll(t *testing.T) {
	_, _ = ReadAll(bytes.NewReader([]byte{0x40, 0x41, 0x42}), "codeSnippet")
}
