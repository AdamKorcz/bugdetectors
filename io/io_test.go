package io

import (
	"bytes"
	//"fmt"
	"testing"
)

func TestReadAll(t *testing.T) {
	_, _ = ReadAll(bytes.NewReader([]byte{0x40, 0x41, 0x42}), "codeSnippet")
}

func TestGetDescription(t *testing.T) {
	want := `
# (This bug detector is currently in beta)

# A large buffer can be passed to an API that can exhaust the machines memory.
# The fuzzer was able to pass a buffer with a length larger than 500000.
# Because of that there is reason to believe there is no uppper limit to the size of the buffer.
# For more information on the security implications, see "CWE-400: Uncontrolled Resource Consumption".

# The vulnerable API is:

line1.go

# To mitigate this issue, it is advised to add a limit to the bytes being read. 
# If this line reads untrusted input, it should be triaged 
# for the possibility of exploiting this in a real-world scenario.
# If it can be exploited, then the issue is a security vulnerability.
`
	returnString := GetDescription("line1.go")
	if returnString != want {
		t.Fatalf("returnString: \n%s\n\nline1String:\n%s\n", returnString, want)
	}
}
