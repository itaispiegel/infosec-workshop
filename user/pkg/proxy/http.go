package proxy

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/rs/zerolog/log"
)

var (
	firewallExternalIpAddress = [4]byte{10, 1, 2, 3}
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
	proxyListener, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	defer proxyListener.Close()

	for {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			return err
		}

		go p.handleConnection(clientConn)
	}
}

func (p *HttpProxy) handleConnection(proxyToClientConn net.Conn) {
	defer proxyToClientConn.Close()
	clientAddr := proxyToClientConn.RemoteAddr()
	log.Debug().Msgf("Accepted connection from %s", clientAddr)
	serverAddr, err := lookupPeerAddr(clientAddr)
	if err != nil {
		log.Error().Err(err).Msg("Error looking up server address in the connections table")
		return
	}
	log.Info().Str("serverAddr", serverAddr.String()).Msg("Forwarding session to server")

	proxyToServerConn, err := connectToServer(clientAddr, serverAddr)
	if err != nil {
		log.Error().Err(err).Msg("Error connecting to server")
		return
	}
	defer proxyToServerConn.Close()

	done := make(chan struct{})
	go func() {
		defer proxyToClientConn.Close()
		defer proxyToServerConn.Close()
		io.Copy(proxyToServerConn, proxyToClientConn)
		done <- struct{}{}
	}()

	go func() {
		defer proxyToClientConn.Close()
		defer proxyToServerConn.Close()
		io.Copy(proxyToClientConn, proxyToServerConn)
		done <- struct{}{}
	}()

	<-done
	<-done
}

func connectToServer(clientAddr net.Addr, serverAddr *net.TCPAddr) (net.Conn, error) {
	proxyToServerSock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	defer syscall.Close(proxyToServerSock)

	if err := syscall.Bind(proxyToServerSock, &syscall.SockaddrInet4{Port: 0, Addr: firewallExternalIpAddress}); err != nil {
		return nil, err
	}

	sockAddr, err := syscall.Getsockname(proxyToServerSock)
	if err != nil {
		return nil, err
	}

	proxyPort := uint16(sockAddr.(*syscall.SockaddrInet4).Port)
	log.Debug().Uint16("proxyPort", proxyPort).Msgf("Setting proxy port")
	setProxyPort(clientAddr, serverAddr, proxyPort)

	if err := syscall.Connect(proxyToServerSock, &syscall.SockaddrInet4{Port: serverAddr.Port, Addr: [4]byte(serverAddr.AddrPort().Addr().As4())}); err != nil {
		return nil, err
	}

	proxyToServerConn, err := net.FileConn(os.NewFile(uintptr(proxyToServerSock), "socket"))
	return proxyToServerConn, err
}
