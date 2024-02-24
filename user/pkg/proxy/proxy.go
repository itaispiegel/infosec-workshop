package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/itaispiegel/infosec-workshop/user/pkg/conntrack"
	"github.com/itaispiegel/infosec-workshop/user/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	setProxyPortFile = "/sys/class/fw/proxy_port/proxy_port"
)

type Proxy interface {
	Start() error
	handleConnection() error
}

func lookupPeerAddr(addr net.Addr) (*net.TCPAddr, error) {
	connections, err := conntrack.ReadConnections()
	if err != nil {
		return nil, err
	}

	addrParts := strings.Split(addr.String(), ":")
	addrIp := [4]byte(net.ParseIP(addrParts[0]).To4())
	addrPortInt, _ := strconv.Atoi(addrParts[1])
	addrPort := uint16(addrPortInt)

	log.Debug().Str("addr", addr.String()).Msg("Looking up peer address")

	for _, conn := range connections {
		if conn.SrcIp == addrIp && conn.SrcPort == uint16(addrPort) {
			return &net.TCPAddr{
				IP:   conn.DestIp[:],
				Port: int(conn.DestPort),
			}, nil
		}
	}

	return nil, errors.New("no matching connection found")
}

func setProxyPort(clientAddr, serverAddr net.Addr, proxyPort uint16) {
	clientAddrParts := strings.Split(clientAddr.String(), ":")
	clientAddrIp := [4]byte(net.ParseIP(clientAddrParts[0]).To4())
	clientAddrPortInt, _ := strconv.Atoi(clientAddrParts[1])
	clientAddrPort := uint16(clientAddrPortInt)

	serverAddrParts := strings.Split(serverAddr.String(), ":")
	serverAddrIp := [4]byte(net.ParseIP(serverAddrParts[0]).To4())
	serverAddrPortInt, _ := strconv.Atoi(serverAddrParts[1])
	serverAddrPort := uint16(serverAddrPortInt)

	buf := bytes.NewBuffer(nil)
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, clientAddrIp))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, clientAddrPort))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, serverAddrIp))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, serverAddrPort))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, proxyPort))

	if err := os.WriteFile(setProxyPortFile, buf.Bytes(), 0); err != nil {
		panic(err)
	}
}
