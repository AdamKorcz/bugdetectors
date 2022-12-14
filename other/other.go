package other

import (
	"fmt"
	"strings"
)

var MaxBufferSize = 1000000

func GetDescription() string {
	var sb strings.Builder

	sb.WriteString("\n# (This bug detector is currently in beta) \n")
	sb.WriteString("\n We have found an issue \n")
	sb.WriteString("\n")
	return sb.String()
}

func CheckLen(b []byte, i interface{}) {
	fmt.Println(reflect.TypeOf(i))
	/*if len(b) > MaxBufferSize {
		panic(GetDescription())
	}
	return b*/
}
