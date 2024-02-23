package proxy

import (
	"errors"
	"net"

	"github.com/itaispiegel/infosec-workshop/user/pkg/conntrack"
)

const (
	setProxyPortFile = "/sys/class/fw/proxy_port/proxy_port"
)

type Proxy interface {
	Start() error
	handleConnection() error
}

func lookupDestinationAddr(srcIp [4]byte, srcPort uint16) (*net.TCPAddr, error) {
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

// func setProxyPort(srcIp [4]byte, srcPort uint16, destIp [4]byte, destPort uint16, proxyPort uint16) {
// 	buf := bytes.NewBuffer(nil)
// 	utils.PanicIfError(binary.Write(buf, binary.BigEndian, srcIp))
// 	utils.PanicIfError(binary.Write(buf, binary.BigEndian, srcPort))
// 	utils.PanicIfError(binary.Write(buf, binary.BigEndian, destIp))
// 	utils.PanicIfError(binary.Write(buf, binary.BigEndian, destPort))
// 	utils.PanicIfError(binary.Write(buf, binary.BigEndian, proxyPort))

// 	if err := os.WriteFile(setProxyPortFile, buf.Bytes(), 0); err != nil {
// 		panic(err)
// 	}
// }
