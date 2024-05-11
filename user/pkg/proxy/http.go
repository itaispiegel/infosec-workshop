package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	cparser "github.com/itaispiegel/infosec-workshop/user/cparser"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var dangerousContentTypes = []string{
	"text/csv",
	"application/zip",
	"text/x-chdr",
	"text/x-csrc",
}

// Sends a 403 Forbidden response to the client with the given reason
func sendBlockedResponse(dest net.Conn, reason string) error {
	msg := fmt.Sprintf("Blocked by Firewall (%s)\n", reason)
	resp := http.Response{
		Status:     "403 Forbidden",
		StatusCode: 403,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: map[string][]string{
			"Content-Type": {"text/plain"},
		},
		Body: io.NopCloser(strings.NewReader(msg)),
	}

	return resp.Write(dest)
}

// Extract the data from the HTTP request, and return it.
// If the data doesn't have headers, return it as is.
func extractHttpData(payload []byte) []byte {
	bodyStartIndex := strings.Index(string(payload), "\r\n\r\n")
	if bodyStartIndex == -1 {
		return payload
	}
	if len(payload) < bodyStartIndex+4 {
		return []byte{}
	}
	return payload[bodyStartIndex+4:]
}

// Get the content type from the HTTP headers.
func getContentTypeFromData(data []byte) string {
	matches := regexp.MustCompile("Content-Type: (.*)\r\n").FindSubmatch(data)
	if len(matches) > 1 {
		return string(matches[1])
	}
	return ""
}

func blockFilesCallback(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	for i := range dangerousContentTypes {
		if contentType := getContentTypeFromData(data); contentType == dangerousContentTypes[i] {
			if err := sendBlockedResponse(dest, contentType); err != nil {
				logger.Error().Err(err).Msg("Error sending blocked response")
				return false
			}

			logger.Warn().Str("srcAddr", dest.LocalAddr().String()).
				Str("destAddr", dest.RemoteAddr().String()).
				Str("contentType", contentType).
				Msg("Blocked file")
			return false
		}
	}

	responseData := extractHttpData(data)
	if cparser.Parse(string(responseData)).Success {
		if err := sendBlockedResponse(dest, "C code detected"); err != nil {
			logger.Error().Err(err).Msg("Error sending blocked response")
			return false
		}

		log.Warn().Str("srcAddr", dest.LocalAddr().String()).
			Str("destAddr", dest.RemoteAddr().String()).
			Msg("Blocking detected C code")
		return false
	}

	if _, err := dest.Write(data); err != nil {
		logger.Error().Err(err).Msg("Error forwarding data")
		return false
	}
	return true
}

func NewHttpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:               "http",
		Address:                address,
		Port:                   port,
		ClientToServerCallback: DefaultCallback,
		ServerToClientCallback: blockFilesCallback,
	}
}
