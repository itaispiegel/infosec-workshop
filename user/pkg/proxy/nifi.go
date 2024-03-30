package proxy

import (
	"net"

	"github.com/rs/zerolog"
)

func nifiCallback(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	logger.Info().Msg("Received data")
	if _, err := dest.Write(data); err != nil {
		logger.Error().Err(err).Msg("Error forwarding data")
		return false
	}
	return true
}

func NewNifiProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:       "nifi",
		Address:        address,
		Port:           port,
		PacketCallback: nifiCallback,
	}
}
