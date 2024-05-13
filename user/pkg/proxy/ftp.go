package proxy

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/itaispiegel/infosec-workshop/user/pkg/conntrack"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	ftpServerDataPort = 20
)

func NewFtpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:               "ftp",
		Address:                address,
		Port:                   port,
		ClientToServerCallback: allowFtpDataConnection,
		ServerToClientCallback: DefaultCallback,
	}
}

// Extracts the IP address and port from the PORT command in the FTP protocol.
// The PORT command is in the format "PORT a,b,c,d,e,f", where a,b,c,d are the IP address octets,
// and e,f are the port number.
// Converts the IP address to a net.TCPAddr, and returns it.
func extractFtpDataBindAddr(numbers string) (*net.TCPAddr, error) {
	numbersArray := strings.Split(numbers, ",")
	octets := make([]byte, 6)

	for i := 0; i < len(octets); i++ {
		octet, err := strconv.Atoi(string(numbersArray[i]))
		if err != nil {
			return nil, err
		}
		octets[i] = uint8(octet)
	}

	tcpAddr := net.TCPAddr{
		IP:   net.IPv4(octets[0], octets[1], octets[2], octets[3]),
		Port: int(octets[4])*256 + int(octets[5]),
	}
	return &tcpAddr, nil
}

// Receives an IP address, and returns a string representation of it in the FTP format.
func ipToFtpRepresentation(ip net.IP) string {
	ipv4Addr := ip.To4()
	return fmt.Sprintf("%d,%d,%d,%d", ipv4Addr[0], ipv4Addr[1], ipv4Addr[2], ipv4Addr[3])
}

// Creates a PORT command payload for the FTP server with the given IP address and port.
func createPortCommandPayload(ipAddr net.IP, port int) string {
	return fmt.Sprintf("PORT %s,%d,%d\r\n",
		ipToFtpRepresentation(ipAddr),
		port/256, port%256,
	)
}

// Callback function that allows FTP data connections.
// It extracts the client's data connection address from the PORT command,
// and allows the connection in the firewall.
// It then sends the PORT command to the server with the proxy's IP address.
func allowFtpDataConnection(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	if pattern := regexp.MustCompile(`PORT ((?:\d+,){5}\d+)`); pattern.Match(data) {
		submatches := pattern.FindSubmatch(data)
		clientDataAddr, err := extractFtpDataBindAddr(string(submatches[1]))
		if err != nil {
			log.Error().Err(err).
				Str("clientAddr", dest.LocalAddr().String()).
				Str("serverAddr", dest.RemoteAddr().String()).
				Msg("Error extracting FTP data connection bind address, blocking connection")
			return false
		}
		serverDataAddr := dest.RemoteAddr().(*net.TCPAddr)
		serverDataAddr.Port = ftpServerDataPort
		dataConnection := conntrack.NewConnection(clientDataAddr, serverDataAddr)
		if err := conntrack.AllowRelatedConnection(dataConnection); err != nil {
			log.Error().Err(err).
				Str("clientAddr", clientDataAddr.String()).
				Str("serverAddr", serverDataAddr.String()).
				Msg("Error allowing FTP data connection, blocking connection")
			return false
		}

		proxyIpAddr := dest.LocalAddr().(*net.TCPAddr).IP
		payloadToServer := createPortCommandPayload(proxyIpAddr, clientDataAddr.Port)
		if _, err := dest.Write([]byte(payloadToServer)); err != nil {
			log.Error().Err(err).
				Str("clientAddr", clientDataAddr.String()).
				Str("serverAddr", serverDataAddr.String()).
				Msg("Error sending FTP data connection payload to server, blocking connection")
			return false
		}
		log.Info().
			Str("bindAddr", clientDataAddr.String()).
			Str("serverAddr", serverDataAddr.String()).
			Msg("Successfully allowed new FTP data connection")
	} else {
		if _, err := dest.Write(data); err != nil {
			logger.Error().Err(err).Msg("Error forwarding data")
			return false
		}
	}
	return true
}
