package proxy

import (
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"slices"
	"strings"

	cparser "github.com/itaispiegel/infosec-workshop/user/cparser"
	"github.com/rs/zerolog"
)

var (
	contentTypeHeaderName   = "Content-Type"
	plainTextContentType    = "text/plain"
	cSourceCodeContentTypes = []string{"text/x-csrc", "text/x-chdr"}
)

func NewSmtpProxy(address string, port uint16) *Proxy {
	return &Proxy{
		Protocol:               "smtp",
		Address:                address,
		Port:                   port,
		ClientToServerCallback: blockCSourceCodeCallback,
		ServerToClientCallback: DefaultCallback,
	}
}

// Removes the QUIT command from the body.
func extractDataFromBody(body string) string {
	return strings.ReplaceAll(body, ".\r\nQUIT\r\n", "")
}

// Returns true whether the media type is a multipart message.
func isMultipartMessage(mediaType string) bool {
	return strings.HasPrefix(mediaType, "multipart")
}

// Returns true whether the content type is C source code.
func isCSourceCodeContentType(contentType string) bool {
	return slices.Contains(cSourceCodeContentTypes, contentType)
}

// Returns true whether the body contains C source code.
// We assume that the body is C source code if the content type is C source code
// or if the content type is plain text and the body is C source code.
// If we're unable to determine, we classify the body as not containing C source code, to not have false positives.
// A log is written in case that we're unable to parse the body.
func isBodyCSourceCode(bodyReader io.Reader, contentType string, logger zerolog.Logger) bool {
	if isCSourceCodeContentType(contentType) {
		return true
	} else if contentType == plainTextContentType {
		body, err := io.ReadAll(bodyReader)
		if err != nil {
			logger.Warn().Err(err).Msg("Error reading the email's body")
			return false
		}
		return cparser.Parse(string(body)).Success
	}
	return false
}

// Receives a multipart message and returns whether it contains a part with C source code.
func hasPartWithCSourceCode(body io.Reader, params map[string]string, logger zerolog.Logger) bool {
	boundary := params["boundary"]
	reader := multipart.NewReader(body, boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return false
		}
		contentType := part.Header.Get(contentTypeHeaderName)
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			logger.Warn().Err(err).Msg("Error parsing the email's media type, continuing")
			return false
		}
		if isBodyCSourceCode(part, mediaType, logger) {
			return true
		}
	}
}

// Returns true whether the email contains C source code.
// If we're unable to determine, we classify the email as not containing C source code, to not have false positives.
// A log is written in case that we're unable to parse the email.
func doesEmailContainCSourceCode(m *mail.Message, logger zerolog.Logger) bool {
	contentType := m.Header.Get(contentTypeHeaderName)
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		logger.Warn().Err(err).Msg("Error parsing the email's media type, continuing")
		return false
	}

	if isCSourceCodeContentType(mediaType) {
		logger.Info().Msg("Blocked email with C source code, by the Content-Type header")
		return true
	} else if mediaType == plainTextContentType {
		body, err := io.ReadAll(m.Body)
		if err != nil {
			logger.Warn().Err(err).Msg("Error reading the email's body")
			return false
		}
		bodyData := extractDataFromBody(string(body))
		if cparser.Parse(bodyData).Success {
			logger.Info().Msg("Blocked plain text email with C source code")
			return true
		} else {
			logger.Info().Msg("Passing on plain text email with non C source code")
			return false
		}
	} else if isMultipartMessage(mediaType) {
		if hasPartWithCSourceCode(m.Body, params, logger) {
			logger.Info().Msg("Blocked multipart email with C source code")
			return true
		} else {
			logger.Info().Msg("Passing on multipart email with non C source code")
			return false
		}
	} else {
		logger.Warn().
			Str("mediaType", mediaType).
			Msg("Received email with unhandled media type")
		return false
	}
}

// Blocks emails with C source code.
func blockCSourceCodeCallback(data []byte, dest net.Conn, logger zerolog.Logger) bool {
	r := strings.NewReader(string(data))
	if m, err := mail.ReadMessage(r); err == nil {
		logger.Info().Msg("Got a new email")
		if doesEmailContainCSourceCode(m, logger) {
			return false
		}
	}
	if _, err := dest.Write(data); err != nil {
		logger.Error().Err(err).Msg("Error forwarding data")
		return false
	}
	return true
}
