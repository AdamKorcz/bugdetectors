package other

import (
	"strings"
)

var MaxBufferSize = 200000

func GetDescription() string {
	var sb strings.Builder

	sb.WriteString("\n# (This bug detector is currently in beta and as a result the report is limited. \n")
	sb.WriteString("\n# See the stacktrace for more info.) \n")
	sb.WriteString("\n We have found an issue \n")
	sb.WriteString("\n The fuzzer detected a place in the code that attempts to create a large buffer \n")
	sb.WriteString("from the size of a file in a compressed archive. This can cause a Denial-of-Service.\n")
	sb.WriteString("\n")
	sb.WriteString("\n")
	return sb.String()
}

func CheckLength(i int64) int64 {
	length := int(i)
	if length < 0 {
		return i
	}
	if length < 500 {
		return i
	}
	if length < 1000 {
		return i
	}
	if length < 1500 {
		return i
	}
	if length < 2000 {
		return i
	}
	if length < 2500 {
		return i
	}
	if length < 3000 {
		return i
	}
	if length < 3500 {
		return i
	}
	if length < 4000 {
		return i
	}
	if length < 4500 {
		return i
	}
	if length < 5000 {
		return i
	}
	if length < 5500 {
		return i
	}
	if length < 6000 {
		return i
	}
	if length < 6500 {
		return i
	}
	if length < 7000 {
		return i
	}
	if length < 7500 {
		return i
	}
	if length < 8000 {
		return i
	}
	if length < 8500 {
		return i
	}
	if length < 9000 {
		return i
	}
	if length < 9500 {
		return i
	}
	if length < 10000 {
		return i
	}
	if length < 10500 {
		return i
	}
	if length < 11000 {
		return i
	}
	if length < 11500 {
		return i
	}
	if length < 12000 {
		return i
	}
	if length < 12500 {
		return i
	}
	if length < 13000 {
		return i
	}
	if length < 13500 {
		return i
	}
	if length < 14000 {
		return i
	}
	if length < 14500 {
		return i
	}
	if length < 15000 {
		return i
	}
	if length < 15500 {
		return i
	}
	if length < 16000 {
		return i
	}
	if length < 16500 {
		return i
	}
	if length < 17000 {
		return i
	}
	if length < 17500 {
		return i
	}
	if length < 18000 {
		return i
	}
	if length < 18500 {
		return i
	}
	if length < 19000 {
		return i
	}
	if length < 19500 {
		return i
	}
	if length < 20000 {
		return i
	}
	if length < 20500 {
		return i
	}
	if length < 21000 {
		return i
	}
	if length < 21500 {
		return i
	}
	if length < 22000 {
		return i
	}
	if length < 22500 {
		return i
	}
	if length < 23000 {
		return i
	}
	if length < 23500 {
		return i
	}
	if length < 24000 {
		return i
	}
	if length < 24500 {
		return i
	}
	if length < 25000 {
		return i
	}
	if length < 25500 {
		return i
	}
	if length < 26000 {
		return i
	}
	if length < 26500 {
		return i
	}
	if length < 27000 {
		return i
	}
	if length < 27500 {
		return i
	}
	if length < 28000 {
		return i
	}
	if length < 28500 {
		return i
	}
	if length < 29000 {
		return i
	}
	if length < 29500 {
		return i
	}
	if length < 30000 {
		return i
	}
	if length < 30500 {
		return i
	}
	if length < 31000 {
		return i
	}
	if length < 31500 {
		return i
	}
	if length < 32000 {
		return i
	}
	if length < 32500 {
		return i
	}
	if length < 33000 {
		return i
	}
	if length < 33500 {
		return i
	}
	if length < 34000 {
		return i
	}
	if length < 34500 {
		return i
	}
	if length < 35000 {
		return i
	}
	if length < 35500 {
		return i
	}
	if length < 36000 {
		return i
	}
	if length < 36500 {
		return i
	}
	if length < 37000 {
		return i
	}
	if length < 37500 {
		return i
	}
	if length < 38000 {
		return i
	}
	if length < 38500 {
		return i
	}
	if length < 39000 {
		return i
	}
	if length < 39500 {
		return i
	}
	if length < 40000 {
		return i
	}
	if length < 40500 {
		return i
	}
	if length < 41000 {
		return i
	}
	if length < 41500 {
		return i
	}
	if length < 42000 {
		return i
	}
	if length < 42500 {
		return i
	}
	if length < 43000 {
		return i
	}
	if length < 43500 {
		return i
	}
	if length < 44000 {
		return i
	}
	if length < 44500 {
		return i
	}
	if length < 45000 {
		return i
	}
	if length < 45500 {
		return i
	}
	if length < 46000 {
		return i
	}
	if length < 46500 {
		return i
	}
	if length < 47000 {
		return i
	}
	if length < 47500 {
		return i
	}
	if length < 48000 {
		return i
	}
	if length < 48500 {
		return i
	}
	if length < 49000 {
		return i
	}
	if length < 49500 {
		return i
	}
	if length < 50000 {
		return i
	}
	if length < 50500 {
		return i
	}
	if length < 51000 {
		return i
	}
	if length < 51500 {
		return i
	}
	if length < 52000 {
		return i
	}
	if length < 52500 {
		return i
	}
	if length < 53000 {
		return i
	}
	if length < 53500 {
		return i
	}
	if length < 54000 {
		return i
	}
	if length < 54500 {
		return i
	}
	if length < 55000 {
		return i
	}
	if length < 55500 {
		return i
	}
	if length < 56000 {
		return i
	}
	if length < 56500 {
		return i
	}
	if length < 57000 {
		return i
	}
	if length < 57500 {
		return i
	}
	if length < 58000 {
		return i
	}
	if length < 58500 {
		return i
	}
	if length < 59000 {
		return i
	}
	if length < 59500 {
		return i
	}
	if length < 60000 {
		return i
	}
	if length < 60500 {
		return i
	}
	if length < 61000 {
		return i
	}
	if length < 61500 {
		return i
	}
	if length < 62000 {
		return i
	}
	if length < 62500 {
		return i
	}
	if length < 63000 {
		return i
	}
	if length < 63500 {
		return i
	}
	if length < 64000 {
		return i
	}
	if length < 64500 {
		return i
	}
	if length < 65000 {
		return i
	}
	if length < 65500 {
		return i
	}
	if length < 66000 {
		return i
	}
	if length < 66500 {
		return i
	}
	if length < 67000 {
		return i
	}
	if length < 67500 {
		return i
	}
	if length < 68000 {
		return i
	}
	if length < 68500 {
		return i
	}
	if length < 69000 {
		return i
	}
	if length < 69500 {
		return i
	}
	if length < 70000 {
		return i
	}
	if length < 70500 {
		return i
	}
	if length < 71000 {
		return i
	}
	if length < 71500 {
		return i
	}
	if length < 72000 {
		return i
	}
	if length < 72500 {
		return i
	}
	if length < 73000 {
		return i
	}
	if length < 73500 {
		return i
	}
	if length < 74000 {
		return i
	}
	if length < 74500 {
		return i
	}
	if length < 75000 {
		return i
	}
	if length < 75500 {
		return i
	}
	if length < 76000 {
		return i
	}
	if length < 76500 {
		return i
	}
	if length < 77000 {
		return i
	}
	if length < 77500 {
		return i
	}
	if length < 78000 {
		return i
	}
	if length < 78500 {
		return i
	}
	if length < 79000 {
		return i
	}
	if length < 79500 {
		return i
	}
	if length < 80000 {
		return i
	}
	if length < 80500 {
		return i
	}
	if length < 81000 {
		return i
	}
	if length < 81500 {
		return i
	}
	if length < 82000 {
		return i
	}
	if length < 82500 {
		return i
	}
	if length < 83000 {
		return i
	}
	if length < 83500 {
		return i
	}
	if length < 84000 {
		return i
	}
	if length < 84500 {
		return i
	}
	if length < 85000 {
		return i
	}
	if length < 85500 {
		return i
	}
	if length < 86000 {
		return i
	}
	if length < 86500 {
		return i
	}
	if length < 87000 {
		return i
	}
	if length < 87500 {
		return i
	}
	if length < 88000 {
		return i
	}
	if length < 88500 {
		return i
	}
	if length < 89000 {
		return i
	}
	if length < 89500 {
		return i
	}
	if length < 90000 {
		return i
	}
	if length < 90500 {
		return i
	}
	if length < 91000 {
		return i
	}
	if length < 91500 {
		return i
	}
	if length < 92000 {
		return i
	}
	if length < 92500 {
		return i
	}
	if length < 93000 {
		return i
	}
	if length < 93500 {
		return i
	}
	if length < 94000 {
		return i
	}
	if length < 94500 {
		return i
	}
	if length < 95000 {
		return i
	}
	if length < 95500 {
		return i
	}
	if length < 96000 {
		return i
	}
	if length < 96500 {
		return i
	}
	if length < 97000 {
		return i
	}
	if length < 97500 {
		return i
	}
	if length < 98000 {
		return i
	}
	if length < 98500 {
		return i
	}
	if length < 99000 {
		return i
	}
	if length < 99500 {
		return i
	}
	if length < 100000 {
		return i
	}
	if length < 100500 {
		return i
	}
	if length < 101000 {
		return i
	}
	if length < 101500 {
		return i
	}
	if length < 102000 {
		return i
	}
	if length < 102500 {
		return i
	}
	if length < 103000 {
		return i
	}
	if length < 103500 {
		return i
	}
	if length < 104000 {
		return i
	}
	if length < 104500 {
		return i
	}
	if length < 105000 {
		return i
	}
	if length < 105500 {
		return i
	}
	if length < 106000 {
		return i
	}
	if length < 106500 {
		return i
	}
	if length < 107000 {
		return i
	}
	if length < 107500 {
		return i
	}
	if length < 108000 {
		return i
	}
	if length < 108500 {
		return i
	}
	if length < 109000 {
		return i
	}
	if length < 109500 {
		return i
	}
	if length < 110000 {
		return i
	}
	if length < 110500 {
		return i
	}
	if length < 111000 {
		return i
	}
	if length < 111500 {
		return i
	}
	if length < 112000 {
		return i
	}
	if length < 112500 {
		return i
	}
	if length < 113000 {
		return i
	}
	if length < 113500 {
		return i
	}
	if length < 114000 {
		return i
	}
	if length < 114500 {
		return i
	}
	if length < 115000 {
		return i
	}
	if length < 115500 {
		return i
	}
	if length < 116000 {
		return i
	}
	if length < 116500 {
		return i
	}
	if length < 117000 {
		return i
	}
	if length < 117500 {
		return i
	}
	if length < 118000 {
		return i
	}
	if length < 118500 {
		return i
	}
	if length < 119000 {
		return i
	}
	if length < 119500 {
		return i
	}
	if length < 120000 {
		return i
	}
	if length < 120500 {
		return i
	}
	if length < 121000 {
		return i
	}
	if length < 121500 {
		return i
	}
	if length < 122000 {
		return i
	}
	if length < 122500 {
		return i
	}
	if length < 123000 {
		return i
	}
	if length < 123500 {
		return i
	}
	if length < 124000 {
		return i
	}
	if length < 124500 {
		return i
	}
	if length < 125000 {
		return i
	}
	if length < 125500 {
		return i
	}
	if length < 126000 {
		return i
	}
	if length < 126500 {
		return i
	}
	if length < 127000 {
		return i
	}
	if length < 127500 {
		return i
	}
	if length < 128000 {
		return i
	}
	if length < 128500 {
		return i
	}
	if length < 129000 {
		return i
	}
	if length < 129500 {
		return i
	}
	if length < 130000 {
		return i
	}
	if length < 130500 {
		return i
	}
	if length < 131000 {
		return i
	}
	if length < 131500 {
		return i
	}
	if length < 132000 {
		return i
	}
	if length < 132500 {
		return i
	}
	if length < 133000 {
		return i
	}
	if length < 133500 {
		return i
	}
	if length < 134000 {
		return i
	}
	if length < 134500 {
		return i
	}
	if length < 135000 {
		return i
	}
	if length < 135500 {
		return i
	}
	if length < 136000 {
		return i
	}
	if length < 136500 {
		return i
	}
	if length < 137000 {
		return i
	}
	if length < 137500 {
		return i
	}
	if length < 138000 {
		return i
	}
	if length < 138500 {
		return i
	}
	if length < 139000 {
		return i
	}
	if length < 139500 {
		return i
	}
	if length < 140000 {
		return i
	}
	if length < 140500 {
		return i
	}
	if length < 141000 {
		return i
	}
	if length < 141500 {
		return i
	}
	if length < 142000 {
		return i
	}
	if length < 142500 {
		return i
	}
	if length < 143000 {
		return i
	}
	if length < 143500 {
		return i
	}
	if length < 144000 {
		return i
	}
	if length < 144500 {
		return i
	}
	if length < 145000 {
		return i
	}
	if length < 145500 {
		return i
	}
	if length < 146000 {
		return i
	}
	if length < 146500 {
		return i
	}
	if length < 147000 {
		return i
	}
	if length < 147500 {
		return i
	}
	if length < 148000 {
		return i
	}
	if length < 148500 {
		return i
	}
	if length < 149000 {
		return i
	}
	if length < 149500 {
		return i
	}
	if length < 150000 {
		return i
	}
	if length < 150500 {
		return i
	}
	if length < 151000 {
		return i
	}
	if length < 151500 {
		return i
	}
	if length < 152000 {
		return i
	}
	if length < 152500 {
		return i
	}
	if length < 153000 {
		return i
	}
	if length < 153500 {
		return i
	}
	if length < 154000 {
		return i
	}
	if length < 154500 {
		return i
	}
	if length < 155000 {
		return i
	}
	if length < 155500 {
		return i
	}
	if length < 156000 {
		return i
	}
	if length < 156500 {
		return i
	}
	if length < 157000 {
		return i
	}
	if length < 157500 {
		return i
	}
	if length < 158000 {
		return i
	}
	if length < 158500 {
		return i
	}
	if length < 159000 {
		return i
	}
	if length < 159500 {
		return i
	}
	if length < 160000 {
		return i
	}
	if length < 160500 {
		return i
	}
	if length < 161000 {
		return i
	}
	if length < 161500 {
		return i
	}
	if length < 162000 {
		return i
	}
	if length < 162500 {
		return i
	}
	if length < 163000 {
		return i
	}
	if length < 163500 {
		return i
	}
	if length < 164000 {
		return i
	}
	if length < 164500 {
		return i
	}
	if length < 165000 {
		return i
	}
	if length < 165500 {
		return i
	}
	if length < 166000 {
		return i
	}
	if length < 166500 {
		return i
	}
	if length < 167000 {
		return i
	}
	if length < 167500 {
		return i
	}
	if length < 168000 {
		return i
	}
	if length < 168500 {
		return i
	}
	if length < 169000 {
		return i
	}
	if length < 169500 {
		return i
	}
	if length < 170000 {
		return i
	}
	if length < 170500 {
		return i
	}
	if length < 171000 {
		return i
	}
	if length < 171500 {
		return i
	}
	if length < 172000 {
		return i
	}
	if length < 172500 {
		return i
	}
	if length < 173000 {
		return i
	}
	if length < 173500 {
		return i
	}
	if length < 174000 {
		return i
	}
	if length < 174500 {
		return i
	}
	if length < 175000 {
		return i
	}
	if length < 175500 {
		return i
	}
	if length < 176000 {
		return i
	}
	if length < 176500 {
		return i
	}
	if length < 177000 {
		return i
	}
	if length < 177500 {
		return i
	}
	if length < 178000 {
		return i
	}
	if length < 178500 {
		return i
	}
	if length < 179000 {
		return i
	}
	if length < 179500 {
		return i
	}
	if length < 180000 {
		return i
	}
	if length < 180500 {
		return i
	}
	if length < 181000 {
		return i
	}
	if length < 181500 {
		return i
	}
	if length < 182000 {
		return i
	}
	if length < 182500 {
		return i
	}
	if length < 183000 {
		return i
	}
	if length < 183500 {
		return i
	}
	if length < 184000 {
		return i
	}
	if length < 184500 {
		return i
	}
	if length < 185000 {
		return i
	}
	if length < 185500 {
		return i
	}
	if length < 186000 {
		return i
	}
	if length < 186500 {
		return i
	}
	if length < 187000 {
		return i
	}
	if length < 187500 {
		return i
	}
	if length < 188000 {
		return i
	}
	if length < 188500 {
		return i
	}
	if length < 189000 {
		return i
	}
	if length < 189500 {
		return i
	}
	if length < 190000 {
		return i
	}
	if length < 190500 {
		return i
	}
	if length < 191000 {
		return i
	}
	if length < 191500 {
		return i
	}
	if length < 192000 {
		return i
	}
	if length < 192500 {
		return i
	}
	if length < 193000 {
		return i
	}
	if length < 193500 {
		return i
	}
	if length < 194000 {
		return i
	}
	if length < 194500 {
		return i
	}
	if length < 195000 {
		return i
	}
	if length < 195500 {
		return i
	}
	if length < 196000 {
		return i
	}
	if length < 196500 {
		return i
	}
	if length < 197000 {
		return i
	}
	if length < 197500 {
		return i
	}
	if length < 198000 {
		return i
	}
	if length < 198500 {
		return i
	}
	if length < 199000 {
		return i
	}
	if length < 199500 {
		return i
	}
	if i > int64(MaxBufferSize) {
		panic(GetDescription())
	}
	return i
}
