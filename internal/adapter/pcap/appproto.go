package pcap

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"pcapviz/internal/domain"
)

// looksLikeTLS reports whether a TCP payload starts with a TLS record header
// (content type 20-23, version 0x03 0x0x).
func looksLikeTLS(b []byte) bool {
	return len(b) >= 3 && b[0] >= 20 && b[0] <= 23 && b[1] == 0x03
}

// parseTLSClientHello extracts the SNI host from a TLS ClientHello record.
// It walks: TLS record -> Handshake(ClientHello) -> extensions -> server_name.
// Returns ("", false) when the payload is not a ClientHello or has no SNI.
func parseTLSClientHello(b []byte) (string, bool) {
	// TLS record header: type(1)=22 handshake, version(2), length(2)
	if len(b) < 5 || b[0] != 22 {
		return "", false
	}
	rec := b[5:]
	// Handshake header: type(1)=1 ClientHello, length(3)
	if len(rec) < 4 || rec[0] != 1 {
		return "", false
	}
	hs := rec[4:]
	// client_version(2) + random(32)
	if len(hs) < 34 {
		return "", false
	}
	p := hs[34:]
	// session_id
	if len(p) < 1 {
		return "", false
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return "", false
	}
	p = p[sidLen:]
	// cipher_suites
	if len(p) < 2 {
		return "", false
	}
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen {
		return "", false
	}
	p = p[csLen:]
	// compression_methods
	if len(p) < 1 {
		return "", false
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return "", false
	}
	p = p[cmLen:]
	// extensions
	if len(p) < 2 {
		return "", false
	}
	extTotal := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) > extTotal {
		p = p[:extTotal]
	}
	for len(p) >= 4 {
		extType := int(p[0])<<8 | int(p[1])
		extLen := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < extLen {
			return "", false
		}
		body := p[:extLen]
		p = p[extLen:]
		if extType != 0 { // 0 = server_name
			continue
		}
		// server_name_list(2) then entries: type(1) + len(2) + name
		if len(body) < 2 {
			return "", false
		}
		body = body[2:]
		if len(body) < 3 {
			return "", false
		}
		nameType := body[0]
		nameLen := int(body[1])<<8 | int(body[2])
		body = body[3:]
		if nameType != 0 || len(body) < nameLen {
			return "", false
		}
		return string(body[:nameLen]), true
	}
	return "", false
}

// parseHTTP recognises a plaintext HTTP/1.x request or response at the start of
// a TCP payload and extracts the salient fields. Returns nil when the payload
// is not HTTP.
func parseHTTP(b []byte) *domain.AppInfo {
	if len(b) < 5 {
		return nil
	}
	line := b
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		line = b[:i]
	}
	first := strings.TrimSpace(string(line))

	// Response: "HTTP/1.1 200 OK"
	if strings.HasPrefix(first, "HTTP/") {
		parts := strings.SplitN(first, " ", 3)
		if len(parts) >= 2 {
			code, _ := strconv.Atoi(parts[1])
			return &domain.AppInfo{Kind: "http", HTTPStatus: code}
		}
		return nil
	}

	// Request: "GET /path HTTP/1.1"
	method, rest, ok := strings.Cut(first, " ")
	if !ok || !isHTTPMethod(method) {
		return nil
	}
	uri, ver, ok := strings.Cut(rest, " ")
	if !ok || !strings.HasPrefix(ver, "HTTP/") {
		return nil
	}
	info := &domain.AppInfo{Kind: "http", HTTPMethod: method, HTTPURI: uri}
	if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b))); err == nil {
		info.HTTPHost = req.Host
	}
	return info
}

func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE":
		return true
	}
	return false
}
