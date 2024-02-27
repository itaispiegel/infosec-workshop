package proxy

import (
	"net"

	"github.com/rs/zerolog"
)

func allowFtpDataConnection(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	return false
}

func NewFtpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Address:        address,
		Port:           port,
		PacketCallback: allowFtpDataConnection,
	}
}
