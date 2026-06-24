package pcap

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"pcapviz/internal/domain"
)

// Decoder implements port.Decoder: it turns raw packet bytes back into a
// detailed, tree-like decode on demand.
type Decoder struct{}

// NewDecoder returns a stateless decoder.
func NewDecoder() Decoder { return Decoder{} }

// Detail decodes raw bytes (captured with the given link type) into a layered
// view plus a hex dump.
func (Decoder) Detail(raw []byte, linkType, num int) (domain.Detail, error) {
	lt := layers.LinkType(linkType)
	pkt := gopacket.NewPacket(raw, lt, gopacket.DecodeOptions{Lazy: false, NoCopy: true})

	d := domain.Detail{Num: num, HexDump: hex.Dump(raw)}
	for _, l := range pkt.Layers() {
		d.Layers = append(d.Layers, decodeLayer(l))
	}
	if len(d.Layers) == 0 {
		return d, fmt.Errorf("packet %d: no decodable layers", num)
	}
	return d, nil
}

func decodeLayer(l gopacket.Layer) domain.Layer {
	out := domain.Layer{Name: l.LayerType().String()}
	add := func(name, value string) {
		out.Fields = append(out.Fields, domain.Field{Name: name, Value: value})
	}
	switch v := l.(type) {
	case *layers.Ethernet:
		add("Source MAC", v.SrcMAC.String())
		add("Destination MAC", v.DstMAC.String())
		add("EtherType", v.EthernetType.String())
	case *layers.IPv4:
		add("Version", fmt.Sprint(v.Version))
		add("Source", v.SrcIP.String())
		add("Destination", v.DstIP.String())
		add("Protocol", v.Protocol.String())
		add("TTL", fmt.Sprint(v.TTL))
		add("Total Length", fmt.Sprint(v.Length))
		add("Identification", fmt.Sprintf("0x%04x", v.Id))
	case *layers.IPv6:
		add("Source", v.SrcIP.String())
		add("Destination", v.DstIP.String())
		add("Next Header", v.NextHeader.String())
		add("Hop Limit", fmt.Sprint(v.HopLimit))
	case *layers.ARP:
		add("Operation", arpOp(v.Operation))
		add("Sender IP", ipStr(v.SourceProtAddress))
		add("Sender MAC", macStr(v.SourceHwAddress))
		add("Target IP", ipStr(v.DstProtAddress))
		add("Target MAC", macStr(v.DstHwAddress))
	case *layers.TCP:
		add("Source Port", fmt.Sprint(v.SrcPort))
		add("Destination Port", fmt.Sprint(v.DstPort))
		add("Sequence", fmt.Sprint(v.Seq))
		add("Acknowledgment", fmt.Sprint(v.Ack))
		add("Flags", tcpFlags(v))
		add("Window", fmt.Sprint(v.Window))
		add("Payload Length", fmt.Sprint(len(v.Payload)))
	case *layers.UDP:
		add("Source Port", fmt.Sprint(v.SrcPort))
		add("Destination Port", fmt.Sprint(v.DstPort))
		add("Length", fmt.Sprint(v.Length))
		add("Payload Length", fmt.Sprint(len(v.Payload)))
	case *layers.ICMPv4:
		add("Type/Code", v.TypeCode.String())
		add("Id", fmt.Sprint(v.Id))
		add("Seq", fmt.Sprint(v.Seq))
	case *layers.ICMPv6:
		add("Type/Code", v.TypeCode.String())
	case *layers.DNS:
		add("Transaction ID", fmt.Sprintf("0x%04x", v.ID))
		add("Type", qrStr(v.QR))
		add("Questions", fmt.Sprint(v.QDCount))
		add("Answers", fmt.Sprint(v.ANCount))
		for _, q := range v.Questions {
			add("Query", fmt.Sprintf("%s %s", q.Name, q.Type))
		}
		for _, a := range v.Answers {
			if a.IP != nil {
				add("Answer", fmt.Sprintf("%s -> %s", a.Name, a.IP))
			}
		}
	default:
		if lp, ok := l.(gopacket.Layer); ok {
			if pl := lp.LayerPayload(); len(pl) > 0 {
				add("Payload Length", fmt.Sprint(len(pl)))
			}
		}
	}
	return out
}

func tcpFlags(t *layers.TCP) string {
	var f []string
	for _, x := range []struct {
		name string
		on   bool
	}{{"SYN", t.SYN}, {"ACK", t.ACK}, {"PSH", t.PSH}, {"FIN", t.FIN}, {"RST", t.RST}, {"URG", t.URG}, {"ECE", t.ECE}, {"CWR", t.CWR}} {
		if x.on {
			f = append(f, x.name)
		}
	}
	return strings.Join(f, ", ")
}

func arpOp(op uint16) string {
	switch op {
	case layers.ARPRequest:
		return "request (1)"
	case layers.ARPReply:
		return "reply (2)"
	}
	return fmt.Sprint(op)
}

func qrStr(qr bool) string {
	if qr {
		return "response"
	}
	return "query"
}

func ipStr(b []byte) string {
	if len(b) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	return hex.EncodeToString(b)
}

func macStr(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}
