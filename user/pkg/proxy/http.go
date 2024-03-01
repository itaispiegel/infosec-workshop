package proxy

import (
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
)

var dangerousContentTypes = []string{
	"text/csv",
	"application/zip",
}

func sendBlockedResponse(dest net.Conn) {
	resp := http.Response{
		Status:     "403 Forbidden",
		StatusCode: 403,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: map[string][]string{
			"Content-Type": {"text/plain"},
		},
		Body: io.NopCloser(strings.NewReader("Blocked by Firewall\n")),
	}

	resp.Write(dest)
}

func blockDangerousFilesCallback(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	matches := regexp.MustCompile("Content-Type: (.*)\r\n").FindSubmatch(data)
	if len(matches) > 1 {
		contentType := string(matches[1])
		for i := range dangerousContentTypes {
			if contentType == dangerousContentTypes[i] {
				sendBlockedResponse(dest)
				logger.Warn().Str("srcAddr", dest.LocalAddr().String()).
					Str("destAddr", dest.RemoteAddr().String()).
					Msg("Blocked CSV file")
				return false
			}
		}
	}
	dest.Write(data)
	return true
}

func NewHttpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:       "http",
		Address:        address,
		Port:           port,
		PacketCallback: blockDangerousFilesCallback,
	}
}
