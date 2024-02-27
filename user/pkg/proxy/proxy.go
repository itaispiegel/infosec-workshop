package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/itaispiegel/infosec-workshop/user/pkg/conntrack"
	"github.com/itaispiegel/infosec-workshop/user/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	setProxyPortFile = "/sys/class/fw/proxy_port/proxy_port"
)

// PacketCallback is a function that is called when data is received.
// It receives the data and the destination connection,
// and returns a boolean indicating whether to close the connection.
// It can use the dest connection to send custom data.
type PacketCallback func(data []byte, dest net.Conn) bool

type Proxy struct {
	Address string
	Port    uint16
	PacketCallback
}

func (p *Proxy) Start() error {
	bindAddr := fmt.Sprintf("%s:%d", p.Address, p.Port)
	proxyListener, err := net.Listen("tcp4", bindAddr)
	if err != nil {
		return err
	}
	defer proxyListener.Close()

	log.Info().Msgf("Started HTTP proxy server on %s", bindAddr)
	for {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			return err
		}

		go p.handleConnection(clientConn)
	}
}

func (p *Proxy) handleConnection(proxyToClientConn net.Conn) {
	defer proxyToClientConn.Close()
	clientAddr := proxyToClientConn.RemoteAddr().(*net.TCPAddr)
	log.Debug().Msgf("Accepted connection from %s. "+
		"Looking up server address from the connections table", clientAddr)
	serverAddr, err := lookupPeerAddr(clientAddr)
	if err != nil {
		log.Error().Err(err).Msg("Error looking up server address in the connections table")
		return
	}

	proxyToServerConn, err := connectToServer(clientAddr, serverAddr)
	if err != nil {
		log.Error().Err(err).Msg("Error connecting to server")
		return
	}
	defer proxyToServerConn.Close()

	log.Info().
		Str("clientAddr", clientAddr.String()).
		Str("serverAddr", serverAddr.String()).
		Str("proxyAddr", proxyToServerConn.LocalAddr().String()).
		Msg("Forwarding session to server")

	done := make(chan struct{})
	go p.forwardConnections(proxyToServerConn, proxyToClientConn, done)
	go p.forwardConnections(proxyToClientConn, proxyToServerConn, done)

	<-done
	<-done

	log.Info().
		Str("clientAddr", clientAddr.String()).
		Str("serverAddr", serverAddr.String()).
		Str("proxyAddr", proxyToServerConn.LocalAddr().String()).
		Msg("Closed forwarding connection")
}

func (p *Proxy) forwardConnections(source, dest net.Conn, done chan struct{}) {
	buffer := make([]byte, 1024)
	for {
		n, err := source.Read(buffer)
		if errors.Is(err, io.EOF) {
			dest.Close()
			done <- struct{}{}
			return
		} else if errors.Is(err, net.ErrClosed) {
			done <- struct{}{}
			return
		} else if err != nil {
			log.Error().Err(err).Msg("Error reading from server")
			dest.Close()
			done <- struct{}{}
			return
		} else {
			if shouldClose := p.PacketCallback(buffer[:n], dest); shouldClose {
				source.Close()
				dest.Close()
				done <- struct{}{}
				return
			}
		}
	}
}

func connectToServer(clientAddr *net.TCPAddr, serverAddr *net.TCPAddr) (net.Conn, error) {
	proxyToServerSock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	defer syscall.Close(proxyToServerSock)

	if err := syscall.Bind(proxyToServerSock, &syscall.SockaddrInet4{}); err != nil {
		return nil, err
	}

	sockAddr, err := syscall.Getsockname(proxyToServerSock)
	if err != nil {
		return nil, err
	}

	sockAddrInet4, ok := sockAddr.(*syscall.SockaddrInet4)
	if !ok {
		return nil, errors.New("unexpected socket address type")
	}

	proxyPort := uint16(sockAddrInet4.Port)
	setProxyPort(clientAddr, serverAddr, proxyPort)

	serverAddrInet4 := &syscall.SockaddrInet4{Port: serverAddr.Port, Addr: [4]byte(serverAddr.IP.To4())}
	if err := syscall.Connect(proxyToServerSock, serverAddrInet4); err != nil {
		return nil, err
	}

	proxyToServerConn, err := net.FileConn(os.NewFile(uintptr(proxyToServerSock), ""))
	return proxyToServerConn, err
}

func lookupPeerAddr(addr *net.TCPAddr) (*net.TCPAddr, error) {
	connections, err := conntrack.ReadConnections()
	if err != nil {
		return nil, err
	}

	addrIp := [4]byte(addr.IP.To4())
	addrPort := uint16(addr.Port)

	for _, conn := range connections {
		if conn.SrcIp == addrIp && conn.SrcPort == addrPort {
			return &net.TCPAddr{
				IP:   conn.DestIp[:],
				Port: int(conn.DestPort),
			}, nil
		}
	}

	return nil, errors.New("no matching connection found")
}

func setProxyPort(clientAddr, serverAddr *net.TCPAddr, proxyPort uint16) {
	buf := bytes.NewBuffer(nil)
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, [4]byte(clientAddr.IP.To4())))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, uint16(clientAddr.Port)))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, [4]byte(serverAddr.IP.To4())))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, uint16(serverAddr.Port)))
	utils.PanicIfError(binary.Write(buf, binary.BigEndian, proxyPort))

	if err := os.WriteFile(setProxyPortFile, buf.Bytes(), 0); err != nil {
		panic(err)
	}
}
