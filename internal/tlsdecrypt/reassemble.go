package tlsdecrypt

import (
	"net"
	"sort"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type segment struct {
	seq     uint32
	payload []byte
}

type halfStream struct {
	segs []segment
}

type conn struct {
	key       string
	endpoints []string            // up to two "ip:port"
	half      map[string][]segment // keyed by source endpoint
}

// Decrypt reassembles the TCP streams in the capture and decrypts the TLS 1.2
// connections for which the key log provides the master secret.
func Decrypt(frames [][]byte, linkType int, keylog []byte) []Session {
	kl := ParseKeyLog(keylog)
	conns := reassembleAll(frames, linkType)

	var out []Session
	for _, c := range conns {
		client, server, cStream, sStream, ok := c.classify()
		if !ok {
			continue
		}
		s := decryptStreams(cStream, sStream, kl)
		s.Client, s.Server = client, server
		out = append(out, s)
	}
	return out
}

func reassembleAll(frames [][]byte, linkType int) []*conn {
	lt := layers.LinkType(linkType)
	byKey := map[string]*conn{}
	var order []*conn

	for _, data := range frames {
		pkt := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		tcpL := pkt.Layer(layers.LayerTypeTCP)
		if tcpL == nil {
			continue
		}
		tcp := tcpL.(*layers.TCP)
		if len(tcp.Payload) == 0 {
			continue
		}
		src, dst, ok := endpoints(pkt, int(tcp.SrcPort), int(tcp.DstPort))
		if !ok {
			continue
		}
		key := flowKey(src, dst)
		c := byKey[key]
		if c == nil {
			c = &conn{key: key, half: map[string][]segment{}}
			byKey[key] = c
			order = append(order, c)
		}
		if !contains(c.endpoints, src) {
			c.endpoints = append(c.endpoints, src)
		}
		if !contains(c.endpoints, dst) {
			c.endpoints = append(c.endpoints, dst)
		}
		cp := make([]byte, len(tcp.Payload))
		copy(cp, tcp.Payload)
		c.half[src] = append(c.half[src], segment{seq: uint32(tcp.Seq), payload: cp})
	}
	return order
}

func endpoints(pkt gopacket.Packet, srcPort, dstPort int) (string, string, bool) {
	if ip := pkt.Layer(layers.LayerTypeIPv4); ip != nil {
		v := ip.(*layers.IPv4)
		return net.JoinHostPort(v.SrcIP.String(), itoa(srcPort)),
			net.JoinHostPort(v.DstIP.String(), itoa(dstPort)), true
	}
	if ip := pkt.Layer(layers.LayerTypeIPv6); ip != nil {
		v := ip.(*layers.IPv6)
		return net.JoinHostPort(v.SrcIP.String(), itoa(srcPort)),
			net.JoinHostPort(v.DstIP.String(), itoa(dstPort)), true
	}
	return "", "", false
}

// classify reassembles both directions and identifies which side is the client
// (the one whose stream begins with a TLS ClientHello).
func (c *conn) classify() (client, server string, clientStream, serverStream []byte, ok bool) {
	if len(c.endpoints) != 2 {
		return "", "", nil, nil, false
	}
	a, b := c.endpoints[0], c.endpoints[1]
	streamA := reassemble(c.half[a])
	streamB := reassemble(c.half[b])

	switch {
	case isClientHello(streamA):
		return a, b, streamA, streamB, true
	case isClientHello(streamB):
		return b, a, streamB, streamA, true
	}
	return "", "", nil, nil, false
}

// isClientHello reports whether a stream starts with a TLS handshake record
// carrying a ClientHello.
func isClientHello(stream []byte) bool {
	return len(stream) >= 6 && stream[0] == recHandshake && stream[1] == 0x03 && stream[5] == hsClientHello
}

// reassemble orders TCP segments by sequence number into a contiguous byte
// stream, handling retransmissions/overlaps and stopping at the first gap.
func reassemble(segs []segment) []byte {
	if len(segs) == 0 {
		return nil
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].seq < segs[j].seq })
	next := segs[0].seq
	var buf []byte
	for _, s := range segs {
		switch {
		case s.seq == next:
			buf = append(buf, s.payload...)
			next += uint32(len(s.payload))
		case s.seq < next:
			overlap := next - s.seq
			if int(overlap) < len(s.payload) {
				buf = append(buf, s.payload[overlap:]...)
				next += uint32(len(s.payload)) - overlap
			}
		default:
			return buf // gap: stream incomplete
		}
	}
	return buf
}

func flowKey(a, b string) string {
	if a < b {
		return a + "|" + b
	}
	return b + "|" + a
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
