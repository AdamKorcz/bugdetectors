package io

import (
	"bytes"
	"io"
	"strings"
)

var (
	MaxBufferSize = 1000000
)

func GetDescription(faultyLine string) string {
	var sb strings.Builder

	sb.WriteString("\n# (This bug detector is currently in beta)\n")
	sb.WriteString("\n# A large buffer can be passed to an API that can exhaust the machines memory.\n")
	sb.WriteString(`# The fuzzer was able to pass a buffer with a length larger than 1000000.
# Because of that there is reason to believe there is no uppper limit to the size of the buffer.
# For more information on the security implications, see "CWE-400: Uncontrolled Resource Consumption".`)
	sb.WriteString("\n\n# The vulnerable API is:\n\n")
	sb.WriteString(strings.Replace(faultyLine, "NEW_LINE", "\n", -1))
	sb.WriteString("\n\n")
	sb.WriteString(`# To mitigate this issue, it is advised to add a limit to the bytes being read. 
# If this line reads untrusted input, it should be triaged 
# for the possibility of exploiting this in a real-world scenario.
# If it can be exploited, then the issue is a security vulnerability.`)
	sb.WriteString("\n")
	return sb.String()
}

// Checks whether a large reader is passed to io.ReadAll.
// The "s" parameter is a string with the location of the
// faulty code. This is generated during instrumentation.
func ReadAll(r io.Reader, s string) ([]byte, error) {
	buf := new(bytes.Buffer)
	// Read bytes with a limit to not exhaust memory.
	buf.ReadFrom(io.LimitReader(r, 1000000000))
	bufferLength := buf.Len()
	// A bit hacky trick to trick a coverage guided fuzzer
	// into generating a large buffer.
	if bufferLength > 10000 {
		if bufferLength > 50000 {
			if bufferLength > 100000 {
				if bufferLength > 200000 {
					if bufferLength > 500000 {
						if bufferLength > 800000 {
							if bufferLength > MaxBufferSize {
								panic(GetDescription(s))
							}
						}
					}
				}
			}
		}
	}
	return buf.Bytes(), nil
}
