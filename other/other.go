package other

import (
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

func CheckLength(i int) {
	if i > MaxBufferSize {
		panic(GetDescription())
	}
}
