package io

import (
	"bytes"
	"io"
	"strings"
)

var (
	MaxBufferSize = 10000
)

// Checks whether a large reader is passed to io.ReadAll.
// The "s" parameter is a string with the location of the
// faulty code. This is generated during instrumentation.
func ReadAll(r io.Reader, s string) ([]byte, error) {
	buf := new(bytes.Buffer)
	// Read bytes with a limit to not exhaust memory.
	buf.ReadFrom(io.LimitReader(r, 1500000000))
	bufferLength := buf.Len()
	if bufferLength > MaxBufferSize {
		var msg strings.Builder
		msg.WriteString("A large buffer can be passed to an API that will exhaust this machines memory")
		msg.WriteString("The faulty line:\n")
		msg.WriteString(strings.Replace(s, "NEW_LINE", "\n", -1))
		msg.WriteString("\n")
		msg.WriteString(`To mitigate this issue, it is advised to
			add a limit to the bytes being read.
			If this line reads untrusted input, it should be triaged 
			for the possibility of executing this attack in a real-world 
			scenario. If it can, then the issue is a security vulnerability.`)
		panic(msg.String())
	}
	return buf.Bytes(), nil
}
