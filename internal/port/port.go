// Package port declares the hexagon's ports: the interfaces through which the
// application core talks to the outside world. They are expressed purely in
// terms of domain types so the core never depends on a concrete technology.
package port

import "pcapviz/internal/domain"

// PacketSource is an outbound port that yields the packets of a capture. The
// pcap adapter implements it on top of a .pcap/.pcapng file.
type PacketSource interface {
	// LinkType returns the link-layer type of the capture (gopacket
	// layers.LinkType encoded as an int), needed to re-decode raw bytes later.
	LinkType() int
	// ForEach decodes every packet, calling fn with its summary and the raw
	// bytes. Iteration stops and the error is returned if fn returns one.
	ForEach(fn func(pkt domain.Packet, raw []byte) error) error
}

// IndexStore is an outbound port that keeps the loaded capture in memory and
// serves paginated/filtered access to it. The memstore adapter implements it.
type IndexStore interface {
	SetLinkType(lt int)
	LinkType() int
	Add(pkt domain.Packet, raw []byte)
	Count() int
	All() []domain.Packet
	// Page returns the matching summaries in [offset, offset+limit) plus the
	// total number of matches across the whole capture.
	Page(match func(domain.Packet) bool, offset, limit int) (items []domain.Packet, total int)
	// Raw returns the raw bytes of packet number num (1-based).
	Raw(num int) (raw []byte, ok bool)
	// Raws returns the raw bytes of every packet, in capture order (used for
	// stream reassembly, e.g. TLS decryption).
	Raws() [][]byte
	Reset()
}

// Decoder is an outbound port that turns raw packet bytes into a detailed,
// tree-like decode. The pcap adapter implements it.
type Decoder interface {
	Detail(raw []byte, linkType, num int) (domain.Detail, error)
}
