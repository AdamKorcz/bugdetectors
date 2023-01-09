package io

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

var (
	MaxBufferSize = 200000
)

func GetDescription(faultyLine string) string {
	var sb strings.Builder

	sb.WriteString("\n# (This bug detector is currently in beta)\n")
	sb.WriteString("\n# A large buffer can be passed to an API that can exhaust the machines memory.\n")
	sb.WriteString(fmt.Sprintf(`# The fuzzer was able to pass a buffer with a length larger than %d.
# Because of that there is reason to believe there is no uppper limit to the size of the buffer.
# For more information on the security implications, see "CWE-400: Uncontrolled Resource Consumption".`, MaxBufferSize))
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
	if bufferLength < 100 {
		return buf.Bytes(), nil
	}
	if bufferLength < 200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 700 {
		return buf.Bytes(), nil
	}
	if bufferLength < 1000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 1300 {
		return buf.Bytes(), nil
	}
	if bufferLength < 1700 {
		return buf.Bytes(), nil
	}
	if bufferLength < 2100 {
		return buf.Bytes(), nil
	}
	if bufferLength < 2500 {
		return buf.Bytes(), nil
	}
	if bufferLength < 2700 {
		return buf.Bytes(), nil
	}
	if bufferLength < 3000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 3300 {
		return buf.Bytes(), nil
	}
	if bufferLength < 3700 {
		return buf.Bytes(), nil
	}
	if bufferLength < 4100 {
		return buf.Bytes(), nil
	}
	if bufferLength < 4500 {
		return buf.Bytes(), nil
	}
	if bufferLength < 4700 {
		return buf.Bytes(), nil
	}
	if bufferLength < 5000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 5300 {
		return buf.Bytes(), nil
	}
	if bufferLength < 5700 {
		return buf.Bytes(), nil
	}
	if bufferLength < 6100 {
		return buf.Bytes(), nil
	}
	if bufferLength < 7500 {
		return buf.Bytes(), nil
	}
	if bufferLength < 8700 {
		return buf.Bytes(), nil
	}
	if bufferLength < 9500 {
		return buf.Bytes(), nil
	}
	if bufferLength < 10000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 11000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 13000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 15000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 17000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 19000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 21000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 24000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 27000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 30000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 33000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 36000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 39000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 42000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 45000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 48000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 51000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 54000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 57000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 60000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 63000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 66000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 69000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 72000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 75000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 78000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 81000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 84000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 87000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 90000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 93000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 96000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 99000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 102000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 105000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 108000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 112000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 115000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 118000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 122000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 125000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 128000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 132000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 135000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 138000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 142000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 145000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 148000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 152000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 155000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 158000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 162000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 165000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 168000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 172000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 175000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 178000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 182000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 185000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 188000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 192000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 195000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 198000 {
		return buf.Bytes(), nil
	}
	if bufferLength > MaxBufferSize {
		panic(GetDescription(s))
	}
	return buf.Bytes(), nil
}
