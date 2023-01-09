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
	if bufferLength < 91800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 92000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 92200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 92400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 92600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 92800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 93000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 93200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 93400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 93600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 93800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 94000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 94200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 94400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 94600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 94800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 95000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 95200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 95400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 95600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 95800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 96000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 96200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 96400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 96600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 96800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 97000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 97200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 97400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 97600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 97800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 98000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 98200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 98400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 98600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 98800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 99000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 99200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 99400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 99600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 99800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 100000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 100200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 100400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 100600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 100800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 101000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 101200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 101400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 101600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 101800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 102000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 102200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 102400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 102600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 102800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 103000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 103200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 103400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 103600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 103800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 104000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 104200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 104400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 104600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 104800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 105000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 105200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 105400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 105600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 105800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 106000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 106200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 106400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 106600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 106800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 107000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 107200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 107400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 107600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 107800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 108000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 108200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 108400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 108600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 108800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 109000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 109200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 109400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 109600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 109800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 110000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 110200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 110400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 110600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 110800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 111000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 111200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 111400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 111600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 111800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 112000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 112200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 112400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 112600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 112800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 113000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 113200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 113400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 113600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 113800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 114000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 114200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 114400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 114600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 114800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 115000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 115200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 115400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 115600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 115800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 116000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 116200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 116400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 116600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 116800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 117000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 117200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 117400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 117600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 117800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 118000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 118200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 118400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 118600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 118800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 119000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 119200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 119400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 119600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 119800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 120000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 120200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 120400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 120600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 120800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 121000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 121200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 121400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 121600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 121800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 122000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 122200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 122400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 122600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 122800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 123000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 123200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 123400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 123600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 123800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 124000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 124200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 124400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 124600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 124800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 125000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 125200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 125400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 125600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 125800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 126000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 126200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 126400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 126600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 126800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 127000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 127200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 127400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 127600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 127800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 128000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 128200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 128400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 128600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 128800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 129000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 129200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 129400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 129600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 129800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 130000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 130200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 130400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 130600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 130800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 131000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 131200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 131400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 131600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 131800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 132000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 132200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 132400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 132600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 132800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 133000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 133200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 133400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 133600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 133800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 134000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 134200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 134400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 134600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 134800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 135000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 135200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 135400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 135600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 135800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 136000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 136200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 136400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 136600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 136800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 137000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 137200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 137400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 137600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 137800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 138000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 138200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 138400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 138600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 138800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 139000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 139200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 139400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 139600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 139800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 140000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 140200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 140400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 140600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 140800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 141000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 141200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 141400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 141600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 141800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 142000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 142200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 142400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 142600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 142800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 143000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 143200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 143400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 143600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 143800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 144000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 144200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 144400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 144600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 144800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 145000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 145200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 145400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 145600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 145800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 146000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 146200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 146400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 146600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 146800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 147000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 147200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 147400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 147600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 147800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 148000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 148200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 148400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 148600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 148800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 149000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 149200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 149400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 149600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 149800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 150000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 150200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 150400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 150600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 150800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 151000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 151200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 151400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 151600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 151800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 152000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 152200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 152400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 152600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 152800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 153000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 153200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 153400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 153600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 153800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 154000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 154200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 154400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 154600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 154800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 155000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 155200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 155400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 155600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 155800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 156000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 156200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 156400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 156600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 156800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 157000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 157200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 157400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 157600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 157800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 158000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 158200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 158400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 158600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 158800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 159000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 159200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 159400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 159600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 159800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 160000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 160200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 160400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 160600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 160800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 161000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 161200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 161400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 161600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 161800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 162000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 162200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 162400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 162600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 162800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 163000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 163200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 163400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 163600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 163800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 164000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 164200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 164400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 164600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 164800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 165000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 165200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 165400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 165600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 165800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 166000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 166200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 166400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 166600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 166800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 167000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 167200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 167400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 167600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 167800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 168000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 168200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 168400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 168600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 168800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 169000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 169200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 169400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 169600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 169800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 170000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 170200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 170400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 170600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 170800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 171000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 171200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 171400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 171600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 171800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 172000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 172200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 172400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 172600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 172800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 173000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 173200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 173400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 173600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 173800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 174000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 174200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 174400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 174600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 174800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 175000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 175200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 175400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 175600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 175800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 176000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 176200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 176400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 176600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 176800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 177000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 177200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 177400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 177600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 177800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 178000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 178200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 178400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 178600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 178800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 179000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 179200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 179400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 179600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 179800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 180000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 180200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 180400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 180600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 180800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 181000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 181200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 181400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 181600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 181800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 182000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 182200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 182400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 182600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 182800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 183000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 183200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 183400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 183600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 183800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 184000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 184200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 184400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 184600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 184800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 185000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 185200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 185400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 185600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 185800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 186000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 186200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 186400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 186600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 186800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 187000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 187200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 187400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 187600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 187800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 188000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 188200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 188400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 188600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 188800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 189000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 189200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 189400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 189600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 189800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 190000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 190200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 190400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 190600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 190800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 191000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 191200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 191400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 191600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 191800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 192000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 192200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 192400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 192600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 192800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 193000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 193200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 193400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 193600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 193800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 194000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 194200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 194400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 194600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 194800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 195000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 195200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 195400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 195600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 195800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 196000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 196200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 196400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 196600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 196800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 197000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 197200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 197400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 197600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 197800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 198000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 198200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 198400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 198600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 198800 {
		return buf.Bytes(), nil
	}
	if bufferLength < 199000 {
		return buf.Bytes(), nil
	}
	if bufferLength < 199200 {
		return buf.Bytes(), nil
	}
	if bufferLength < 199400 {
		return buf.Bytes(), nil
	}
	if bufferLength < 199600 {
		return buf.Bytes(), nil
	}
	if bufferLength < 199800 {
		return buf.Bytes(), nil
	}
	if bufferLength > MaxBufferSize {
		panic(GetDescription(s))
	}
	return buf.Bytes(), nil
}
