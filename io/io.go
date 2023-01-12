package io

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

var (
	MaxBufferSize = 92000
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
	if bufferLength < 10200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 10400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 10600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 10800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 11000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 11200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 11400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 11600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 11800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 12000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 12200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 12400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 12600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 12800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 13000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 13200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 13400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 13600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 13800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 14000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 14200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 14400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 14600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 14800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 15000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 15200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 15400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 15600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 15800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 16000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 16200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 16400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 16600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 16800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 17000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 17200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 17400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 17600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 17800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 18000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 18200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 18400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 18600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 18800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 19000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 19200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 19400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 19600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 19800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 20000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 20200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 20400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 20600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 20800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 21000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 21200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 21400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 21600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 21800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 22000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 22200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 22400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 22600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 22800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 23000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 23200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 23400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 23600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 23800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 24000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 24200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 24400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 24600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 24800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 25000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 25200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 25400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 25600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 25800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 26000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 26200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 26400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 26600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 26800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 27000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 27200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 27400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 27600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 27800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 28000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 28200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 28400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 28600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 28800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 29000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 29200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 29400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 29600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 29800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 30000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 30200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 30400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 30600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 30800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 31000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 31200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 31400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 31600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 31800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 32000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 32200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 32400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 32600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 32800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 33000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 33200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 33400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 33600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 33800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 34000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 34200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 34400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 34600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 34800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 35000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 35200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 35400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 35600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 35800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 36000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 36200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 36400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 36600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 36800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 37000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 37200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 37400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 37600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 37800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 38000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 38200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 38400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 38600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 38800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 39000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 39200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 39400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 39600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 39800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 40000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 40200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 40400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 40600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 40800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 41000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 41200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 41400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 41600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 41800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 42000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 42200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 42400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 42600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 42800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 43000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 43200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 43400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 43600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 43800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 44000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 44200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 44400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 44600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 44800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 45000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 45200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 45400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 45600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 45800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 46000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 46200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 46400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 46600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 46800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 47000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 47200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 47400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 47600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 47800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 48000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 48200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 48400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 48600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 48800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 49000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 49200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 49400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 49600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 49800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 50000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 50200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 50400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 50600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 50800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 51000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 51200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 51400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 51600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 51800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 52000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 52200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 52400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 52600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 52800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 53000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 53200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 53400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 53600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 53800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 54000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 54200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 54400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 54600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 54800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 55000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 55200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 55400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 55600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 55800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 56000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 56200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 56400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 56600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 56800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 57000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 57200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 57400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 57600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 57800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 58000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 58200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 58400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 58600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 58800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 59000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 59200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 59400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 59600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 59800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 60000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 60200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 60400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 60600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 60800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 61000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 61200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 61400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 61600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 61800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 62000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 62200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 62400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 62600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 62800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 63000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 63200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 63400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 63600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 63800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 64000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 64200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 64400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 64600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 64800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 65000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 65200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 65400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 65600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 65800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 66000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 66200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 66400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 66600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 66800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 67000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 67200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 67400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 67600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 67800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 68000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 68200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 68400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 68600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 68800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 69000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 69200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 69400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 69600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 69800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 70000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 70200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 70400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 70600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 70800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 71000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 71200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 71400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 71600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 71800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 72000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 72200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 72400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 72600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 72800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 73000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 73200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 73400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 73600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 73800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 74000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 74200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 74400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 74600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 74800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 75000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 75200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 75400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 75600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 75800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 76000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 76200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 76400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 76600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 76800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 77000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 77200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 77400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 77600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 77800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 78000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 78200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 78400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 78600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 78800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 79000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 79200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 79400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 79600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 79800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 80000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 80200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 80400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 80600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 80800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 81000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 81200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 81400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 81600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 81800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 82000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 82200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 82400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 82600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 82800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 83000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 83200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 83400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 83600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 83800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 84000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 84200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 84400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 84600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 84800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 85000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 85200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 85400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 85600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 85800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 86000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 86200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 86400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 86600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 86800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 87000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 87200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 87400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 87600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 87800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 88000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 88200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 88400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 88600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 88800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 89000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 89200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 89400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 89600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 89800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 90000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 90200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 90400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 90600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 90800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 91000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 91200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 91400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 91600 {
		return buf.Bytes(), nil
	}
	if bufferLength > MaxBufferSize {
		panic(GetDescription(s))
	}
	return buf.Bytes(), nil
}
