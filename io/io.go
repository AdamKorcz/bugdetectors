package io

import (
	"bytes"
	"runtime/debug"
	"io"
)

var (
	MaxBufferSize = 10000
)

// Checks whether a large reader is passed to io.ReadAll.
func ReadAll(r io.Reader) ([]byte, error) {
	buf := new(bytes.Buffer)
	// Read bytes with a limit to not exhaust memory.
	buf.ReadFrom(io.LimitReader(r, 2000000000))
	bufferLength := buf.Len()
	if bufferLength > MaxBufferSize {
		debug.PrintStack()
		panic("A large buffer can be passed to an API that will exhaust this machines memory")
	}
	return buf.Bytes(), nil
}
