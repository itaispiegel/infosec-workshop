package conntrack

import (
	"fmt"
	"net"
	"os"

	"github.com/rodaine/table"
)

const (
	ConnsTableDeviceFile = "/sys/class/fw/conn/conns"
	connectionBytesSize  = 15
)

type connectionsSlice []Connection

func ReadConnections() (connectionsSlice, error) {
	buf, err := os.ReadFile(ConnsTableDeviceFile)
	if err != nil {
		return nil, err
	}

	table := []Connection{}
	for i := 0; i < len(buf); i += connectionBytesSize {
		table = append(table, *Unmarshal(buf[i : i+connectionBytesSize]))
	}

	return table, nil
}

func (conns *connectionsSlice) Table() table.Table {
	tbl := table.New("Source", "Dest", "ProxyPort", "State")
	for _, conn := range *conns {
		tbl.AddRow(
			fmt.Sprintf("%s:%d", net.IP(conn.SrcIp[:]), conn.SrcPort),
			fmt.Sprintf("%s:%d", net.IP(conn.DestIp[:]), conn.DestPort),
			conn.ProxyPort,
			conn.State,
		)
	}
	return tbl
}
