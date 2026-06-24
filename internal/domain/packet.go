// Package domain is the pure business core of pcapviz. It defines the data
// model (packets, flows, statistics), the display-filter engine and the
// statistics aggregation. It must not import any technical/infrastructure
// package (no gopacket, no net/http): adapters depend on the domain, never the
// other way around.
package domain

import "time"

// Packet is the lightweight summary kept in memory for every captured packet.
// It carries just enough to display the packet list, evaluate display filters
// and compute statistics. The full layer-by-layer Detail is decoded lazily,
// on demand, from the raw bytes by an adapter.
type Packet struct {
	Num     int       `json:"num"`     // 1-based packet number
	Time    time.Time `json:"time"`    // capture timestamp
	Src     string    `json:"src"`     // source address (IP, or MAC if no L3)
	Dst     string    `json:"dst"`     // destination address
	SrcPort int       `json:"srcPort"` // 0 when not applicable
	DstPort int       `json:"dstPort"` // 0 when not applicable
	Proto   string    `json:"proto"`   // highest meaningful protocol: TCP, UDP, DNS, HTTP, TLS, ICMP, ARP...
	Length  int       `json:"length"`  // total captured length in bytes
	Info    string    `json:"info"`    // human-readable one-line summary
	App     *AppInfo  `json:"app,omitempty"`
}

// AppInfo holds application-layer data extracted at decode time (DNS/HTTP/TLS).
// It feeds both the Info column and the extraction views.
type AppInfo struct {
	Kind       string `json:"kind"` // "dns", "http", "tls"
	DNSName    string `json:"dnsName,omitempty"`
	HTTPMethod string `json:"httpMethod,omitempty"`
	HTTPHost   string `json:"httpHost,omitempty"`
	HTTPURI    string `json:"httpURI,omitempty"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	TLSSNI     string `json:"tlsSNI,omitempty"`
}

// Field is a single decoded attribute (name/value) inside a Layer.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Layer is one protocol layer in the detailed, tree-like decode of a packet.
type Layer struct {
	Name   string  `json:"name"`
	Fields []Field `json:"fields"`
}

// Detail is the full decode of a single packet: its layer tree plus a hex dump
// of the raw bytes. Produced on demand by a Decoder adapter.
type Detail struct {
	Num     int     `json:"num"`
	Layers  []Layer `json:"layers"`
	HexDump string  `json:"hexDump"`
}

// Endpoint returns the "ip:port" form of an address, or just the address when
// no transport port applies.
func Endpoint(addr string, port int) string {
	if port == 0 {
		return addr
	}
	return addr + ":" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
