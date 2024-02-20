package proxy

import (
	"errors"
	"net"

	"github.com/itaispiegel/infosec-workshop/user/pkg/conntrack"
)

type Proxy interface {
	Start() error
	handleConnection() error
}

func lookupDestinationAddr(srcIp [4]byte, srcPort uint16) (net.Addr, error) {
	connections, err := conntrack.ReadConnections()
	if err != nil {
		return nil, err
	}

	for _, conn := range connections {
		if conn.SrcIp == srcIp && conn.SrcPort == srcPort {
			return &net.TCPAddr{
				IP:   conn.DestIp[:],
				Port: int(conn.DestPort),
			}, nil
		}
	}

	return nil, errors.New("no matching connection found")
}
