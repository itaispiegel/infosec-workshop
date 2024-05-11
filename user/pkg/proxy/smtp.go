package proxy

import (
	"io"
	"net"
	"net/mail"
	"strings"

	"github.com/itaispiegel/infosec-workshop/user/cparser"
	"github.com/rs/zerolog"
)

func blockCSourceCode(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	r := strings.NewReader(string(data))
	m, err := mail.ReadMessage(r)
	if err != nil {
		logger.Error().Err(err).Msg("Passing on non mail data")
		return true
	}

	body, err := io.ReadAll(m.Body)
	if err != nil {
		logger.Error().Err(err).Msg("Error reading mail body")
		return false
	}

	if cparser.Parse(string(body)).Success {
		logger.Info().Msg("Blocked mail with C source code")
		return false
	}

	return true
}

func NewSmtpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:               "smtp",
		Address:                address,
		Port:                   port,
		ClientToServerCallback: DefaultCallback,
		ServerToClientCallback: blockCSourceCode,
	}
}
