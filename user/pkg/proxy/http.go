package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
)

func rejectCsvFiles(data []byte) bool {
	return !strings.Contains(string(data), "Content-Type: text/csv")
}

func respondBlockedByFirewall(conn net.Conn) {
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

	resp.Write(conn)
}

func NewHttpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Address:                   address,
		Port:                      port,
		PacketFilter:              rejectCsvFiles,
		OnSessionRejectedCallback: respondBlockedByFirewall,
	}
}
