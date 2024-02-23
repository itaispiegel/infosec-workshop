package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

type HttpProxy struct {
	Address string
	Port    uint16
}

func NewHttpProxy(address string, port uint16) *HttpProxy {
	return &HttpProxy{
		Address: address,
		Port:    port,
	}
}

func (p *HttpProxy) Start() error {
	addr := fmt.Sprintf("%s:%d", p.Address, p.Port)
	log.Info().Msgf("Starting HTTP proxy server on %s", addr)
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go p.handleConnection(conn)
	}
}

func (p *HttpProxy) handleConnection(conn net.Conn) {
	log.Debug().Msgf("Accepted connection from %s", conn.RemoteAddr())
	srcAddrParts := strings.Split(conn.RemoteAddr().String(), ":")
	srcIp := net.ParseIP(srcAddrParts[0])
	srcPort, _ := strconv.Atoi(srcAddrParts[1])
	destAddr, err := lookupDestinationAddr([4]byte(srcIp.To4()), uint16(srcPort))
	if err != nil {
		log.Error().Err(err).Msg("Error looking up destination address")
		return
	}

	log.Info().Msgf("Forwarding to %s", destAddr)
	conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
		"Content-Length: 14\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Hello, World!\n"))
	conn.Close()
}
