package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/itaispiegel/infosec-workshop/user/pkg/conntrack"
	"github.com/itaispiegel/infosec-workshop/user/pkg/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	setProxyPortFile   = "/sys/class/fw/conn/proxy_port"
	privateKeySize     = 2048
	certExpirationTime = 365 * 24 * time.Hour
)

// PacketCallback is a function that is called when data is received.
// It receives the data, the destination connection and the logger,
// and returns a boolean indicating whether the connection is valid.
// It can use the dest connection to send custom data.
type PacketCallback func(data []byte, dest net.Conn, logger zerolog.Logger) bool

// A default callback that simply forwards the data to the destination connection.
func DefaultCallback(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	if _, err := dest.Write(data); err != nil {
		logger.Error().Err(err).Msg("Error forwarding data")
		return false
	}
	return true
}

type Proxy struct {
	Protocol               string
	Address                string
	Port                   uint16
	TLSEnabled             bool
	CommonName             string
	ClientToServerCallback PacketCallback
	ServerToClientCallback PacketCallback
}

func (p *Proxy) Start() error {
	bindAddr := fmt.Sprintf("%s:%d", p.Address, p.Port)

	var err error
	var proxyListener net.Listener
	if p.TLSEnabled {
		if proxyListener, err = p.startTlsListener(); err != nil {
			return err
		}
	} else {
		if proxyListener, err = p.startPlainTcpListener(); err != nil {
			return err
		}
	}
	defer proxyListener.Close()

	log.Info().Msgf("Started %s proxy server on %s", p.Protocol, bindAddr)
	return p.handleConnections(proxyListener)
}

// Creates a TLS configuration with a self-signed certificate.
// This is invoked when the proxy is started with the TLSEnabled field set to true.
func (p *Proxy) createTlsConfig() (*tls.Config, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, privateKeySize)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: p.CommonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certExpirationTime),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}

// Returns the address to bind the proxy to.
func (p *Proxy) bindAddr() string {
	return fmt.Sprintf("%s:%d", p.Address, p.Port)
}

// Starts a TLS listener on the proxy's address.
// This is invoked when the proxy is started with the TLSEnabled field set to true.
func (p *Proxy) startTlsListener() (net.Listener, error) {
	var err error
	var tlsConfig *tls.Config
	bindAddr := p.bindAddr()
	if tlsConfig, err = p.createTlsConfig(); err != nil {
		return nil, err
	}
	return tls.Listen("tcp4", bindAddr, tlsConfig)
}

// Starts a plain TCP listener on the proxy's address.
func (p *Proxy) startPlainTcpListener() (net.Listener, error) {
	bindAddr := p.bindAddr()
	return net.Listen("tcp4", bindAddr)
}

// Handles incoming connections on the proxy listener.
func (p *Proxy) handleConnections(proxyListener net.Listener) error {
	for {
		if clientConn, err := proxyListener.Accept(); err != nil {
			return err
		} else {
			go p.handleConnection(clientConn)
		}
	}
}

// Handles a single connection from a client, with the following steps:
// - Looks up the server address from the connections table in the kernel module.
// - Opens a connection to the server.
// - If TLS is enabled, performs a TLS handshake with the server.
// - Forwards data between the client and the server until the session is done.
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	clientAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	log.Info().Msgf("Accepted connection from %s. "+
		"Looking up server address from the connections table", clientAddr)
	serverAddr, err := lookupPeerAddr(clientAddr)
	if err != nil {
		log.Error().Err(err).Msg("Error looking up server address in the connections table")
		return
	}

	log.Debug().Str("serverAddr", serverAddr.String()).
		Msg("Found server address in the connections table")
	serverConn, err := connectToServer(clientAddr, serverAddr)
	if err != nil {
		log.Error().Err(err).Msg("Error connecting to server")
		return
	}
	defer serverConn.Close()

	log.Info().
		Str("clientAddr", clientAddr.String()).
		Str("serverAddr", serverAddr.String()).
		Str("proxyAddr", serverConn.LocalAddr().String()).
		Msg("Forwarding session to server")

	var serverTlsConn *tls.Conn
	done := make(chan struct{})
	if p.TLSEnabled {
		serverTlsConn = tls.Client(serverConn, &tls.Config{InsecureSkipVerify: true})
		if err := serverTlsConn.Handshake(); err != nil {
			log.Error().Err(err).Msg("Error performing TLS handshake with server")
			return
		}
		log.Debug().Msg("TLS handshake with server completed")

		go p.forwardConnections(serverTlsConn, clientConn, p.ServerToClientCallback, done)
		go p.forwardConnections(clientConn, serverTlsConn, p.ClientToServerCallback, done)
	} else {
		go p.forwardConnections(serverConn, clientConn, p.ServerToClientCallback, done)
		go p.forwardConnections(clientConn, serverConn, p.ClientToServerCallback, done)
	}

	<-done
	<-done

	log.Info().
		Str("clientAddr", clientAddr.String()).
		Str("serverAddr", serverAddr.String()).
		Str("proxyAddr", serverConn.LocalAddr().String()).
		Msg("Closed forwarding connection")
}

// Forwards data between two connections, with the following steps:
// - Reads data from the source connection.
// - Calls the callback function with the data, the destination connection and the logger.
// - If the callback returns false, closes both connections and returns.
// - If the source connection is closed, closes the destination connection and returns.
// - If an error occurs while reading from the source connection, closes both connections and returns.
func (p *Proxy) forwardConnections(source, dest net.Conn, callback PacketCallback, done chan struct{}) {
	buffer := make([]byte, 4096)
	for {
		n, err := source.Read(buffer)
		if errors.Is(err, io.EOF) {
			dest.Close()
			done <- struct{}{}
			return
		} else if errors.Is(err, net.ErrClosed) {
			dest.Close()
			done <- struct{}{}
			return
		} else if err != nil {
			log.Error().Err(err).Msg("Error reading from server")
			dest.Close()
			done <- struct{}{}
			return
		} else {
			if isValid := callback(buffer[:n], dest, log.Logger); !isValid {
				source.Close()
				dest.Close()
				done <- struct{}{}
				return
			}
		}
	}
}

// Connects to the server address and returns the connection.
// An important step is setting the proxy port in the kernel module, so the firewall can accept the connections.
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
	log.Debug().Str("serverAddr", serverAddr.IP.String()).
		Uint16("proxyPort", proxyPort).
		Msg("Connecting to server")
	if err := syscall.Connect(proxyToServerSock, serverAddrInet4); err != nil {
		return nil, err
	}
	log.Debug().Str("serverAddr", serverAddr.IP.String()).
		Uint16("proxyPort", proxyPort).
		Msg("Connected to server")

	return net.FileConn(os.NewFile(uintptr(proxyToServerSock), ""))
}

// Looks up the peer address of the client in the connections table in the kernel module.
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

// Update the proxy port in the kernel module.
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
