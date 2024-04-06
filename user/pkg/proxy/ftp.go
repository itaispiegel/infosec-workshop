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

func extractFtpDataBindAddr(numbers string) (*net.TCPAddr, error) {
	tcpAddr := &net.TCPAddr{}
	numbersArray := strings.Split(numbers, ",")
	octets := make([]byte, 6)

	for i := 0; i < len(octets); i++ {
		octet, err := strconv.Atoi(string(numbersArray[i]))
		if err != nil {
			return tcpAddr, err
		}
		octets[i] = uint8(octet)
	}

	tcpAddr.IP = net.IPv4(octets[0], octets[1], octets[2], octets[3])
	tcpAddr.Port = int(octets[4])*256 + int(octets[5])
	return tcpAddr, nil
}

func ipToFtpRepresentation(ip net.IP) string {
	ipv4Addr := ip.To4()
	return fmt.Sprintf("%d,%d,%d,%d", ipv4Addr[0], ipv4Addr[1], ipv4Addr[2], ipv4Addr[3])
}

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
		payloadToServer := fmt.Sprintf("PORT %s,%d,%d\r\n",
			ipToFtpRepresentation(proxyIpAddr),
			clientDataAddr.Port/256, clientDataAddr.Port%256,
		)
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

func NewFtpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:               "ftp",
		Address:                address,
		Port:                   port,
		ClientToServerCallback: allowFtpDataConnection,
		ServerToClientCallback: DefaultCallback,
	}
}
