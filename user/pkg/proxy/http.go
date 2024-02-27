package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
)

func blockCsvCallback(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	var isValid bool
	if isValid = !strings.Contains(string(data), "Content-Type: text/csv"); !isValid {
		dest.Write(data)
	} else {
		msg := "Blocked by Firewall\n"
		readerCloser := io.NopCloser(strings.NewReader(msg))
		resp := http.Response{
			Status:     "403 Forbidden",
			StatusCode: 403,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: map[string][]string{
				"Content-Type": {"text/plain"},
			},
			Body: readerCloser,
		}

		resp.Write(dest)
		logger.Warn().Str("srcAddr", dest.LocalAddr().String()).
			Str("destAddr", dest.RemoteAddr().String()).
			Msg("Blocked CSV file")
	}
	return isValid
}

func NewHttpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:       "http",
		Address:        address,
		Port:           port,
		PacketCallback: blockCsvCallback,
	}
}
