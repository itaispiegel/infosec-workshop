package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	vulnerableEndpoint          = "/nifi-api/controller-services"
	vulnerableDatabaseUrlPrefix = "jdbc:h2"
)

func detectExploit(req *http.Request) bool {
	if req.Method != http.MethodPut || !strings.HasPrefix(req.URL.String(), vulnerableEndpoint) {
		return false
	}

	var data map[string]any
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		log.Error().Err(err).Msg("Error decoding request body")
		return false
	}
	component, ok := data["component"].(map[string]any)
	if !ok {
		return false
	}
	properties, ok := component["properties"].(map[string]any)
	if !ok {
		return false
	}
	databaseUrl, ok := properties["Database Connection URL"].(string)
	if !ok {
		return false
	}

	return strings.HasPrefix(strings.ToLower(databaseUrl), vulnerableDatabaseUrlPrefix)
}

// Protects from CVE 2023-34468
// Works like the official vulnerability fix
// https://github.com/apache/nifi/pull/7349/files
func protectFromCve(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		logger.Error().Err(err).Msg("Error reading request")
		return false
	}

	log.Info().Str("URL", req.URL.String()).
		Str("method", req.Method).
		Msg("Received request")

	if detectExploit(req) {
		log.Error().Msg("H2 database connection URL detected, blocking request")
		return false
	}

	if _, err := dest.Write(data); err != nil {
		logger.Error().Err(err).Msg("Error forwarding data")
		return false
	}
	return true
}

func NewNifiProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:               "nifi",
		Address:                address,
		Port:                   port,
		ServerToClientCallback: DefaultCallback,
		ClientToServerCallback: protectFromCve,
		TLSEnabled:             true,
		CommonName:             "nifi.com",
	}
}
