package pcap

import (
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"pcapviz/internal/domain"
)

// summarize builds the lightweight packet summary kept in memory, including
// application-layer extraction (DNS/HTTP/TLS) used by the Info column, filters
// and statistics.
func summarize(data []byte, lt layers.LinkType, num int, ci gopacket.CaptureInfo) domain.Packet {
	pkt := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	p := domain.Packet{Num: num, Time: ci.Timestamp, Length: ci.Length}
	if p.Length == 0 {
		p.Length = len(data)
	}

	fillNetwork(pkt, &p)
	payload := fillTransport(pkt, &p)
	fillApp(pkt, &p, payload)

	if p.Info == "" {
		p.Info = defaultInfo(p)
	}
	return p
}

func fillNetwork(pkt gopacket.Packet, p *domain.Packet) {
	switch {
	case pkt.Layer(layers.LayerTypeIPv4) != nil:
		v := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		p.Src, p.Dst, p.Proto = v.SrcIP.String(), v.DstIP.String(), "IPv4"
	case pkt.Layer(layers.LayerTypeIPv6) != nil:
		v := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		p.Src, p.Dst, p.Proto = v.SrcIP.String(), v.DstIP.String(), "IPv6"
	case pkt.Layer(layers.LayerTypeARP) != nil:
		v := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
		p.Src = net.IP(v.SourceProtAddress).String()
		p.Dst = net.IP(v.DstProtAddress).String()
		p.Proto = "ARP"
		if v.Operation == layers.ARPRequest {
			p.Info = fmt.Sprintf("Who has %s? Tell %s", p.Dst, p.Src)
		} else {
			p.Info = fmt.Sprintf("%s is at %s", p.Src, net.HardwareAddr(v.SourceHwAddress))
		}
	case pkt.Layer(layers.LayerTypeEthernet) != nil:
		v := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		p.Src, p.Dst, p.Proto = v.SrcMAC.String(), v.DstMAC.String(), v.EthernetType.String()
	}
}

// fillTransport sets ports/proto and returns the transport payload (for app
// detection), if any.
func fillTransport(pkt gopacket.Packet, p *domain.Packet) []byte {
	switch {
	case pkt.Layer(layers.LayerTypeTCP) != nil:
		v := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		p.SrcPort, p.DstPort, p.Proto = int(v.SrcPort), int(v.DstPort), "TCP"
		p.Info = tcpInfo(v)
		return v.Payload
	case pkt.Layer(layers.LayerTypeUDP) != nil:
		v := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		p.SrcPort, p.DstPort, p.Proto = int(v.SrcPort), int(v.DstPort), "UDP"
		return v.Payload
	case pkt.Layer(layers.LayerTypeICMPv4) != nil:
		v := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		p.Proto, p.Info = "ICMP", v.TypeCode.String()
	case pkt.Layer(layers.LayerTypeICMPv6) != nil:
		v := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		p.Proto, p.Info = "ICMPv6", v.TypeCode.String()
	}
	return nil
}

func fillApp(pkt gopacket.Packet, p *domain.Packet, payload []byte) {
	if dns := pkt.Layer(layers.LayerTypeDNS); dns != nil {
		applyDNS(p, dns.(*layers.DNS))
		return
	}
	if len(payload) == 0 {
		return
	}
	if p.SrcPort == 443 || p.DstPort == 443 || looksLikeTLS(payload) {
		if sni, ok := parseTLSClientHello(payload); ok {
			p.Proto = "TLS"
			p.App = &domain.AppInfo{Kind: "tls", TLSSNI: sni}
			p.Info = "Client Hello (SNI: " + sni + ")"
			return
		}
		if looksLikeTLS(payload) {
			p.Proto = "TLS"
			p.Info = "TLS record"
			return
		}
	}
	if h := parseHTTP(payload); h != nil {
		p.Proto = "HTTP"
		p.App = h
		if h.HTTPMethod != "" {
			p.Info = strings.TrimSpace(h.HTTPMethod + " " + h.HTTPURI)
			if h.HTTPHost != "" {
				p.Info += " (Host: " + h.HTTPHost + ")"
			}
		} else if h.HTTPStatus != 0 {
			p.Info = fmt.Sprintf("HTTP response %d", h.HTTPStatus)
		}
	}
}

func applyDNS(p *domain.Packet, d *layers.DNS) {
	p.Proto = "DNS"
	name := ""
	if len(d.Questions) > 0 {
		name = string(d.Questions[0].Name)
	}
	p.App = &domain.AppInfo{Kind: "dns", DNSName: name}
	kind := "query"
	if d.QR {
		kind = "response"
	}
	if name != "" {
		p.Info = fmt.Sprintf("Standard %s 0x%04x %s", kind, d.ID, name)
	} else {
		p.Info = fmt.Sprintf("Standard %s 0x%04x", kind, d.ID)
	}
}

func tcpInfo(t *layers.TCP) string {
	var flags []string
	for name, on := range map[string]bool{
		"SYN": t.SYN, "ACK": t.ACK, "FIN": t.FIN, "RST": t.RST, "PSH": t.PSH, "URG": t.URG,
	} {
		if on {
			flags = append(flags, name)
		}
	}
	// stable order
	order := []string{"SYN", "ACK", "PSH", "FIN", "RST", "URG"}
	var ordered []string
	for _, o := range order {
		for _, f := range flags {
			if f == o {
				ordered = append(ordered, o)
			}
		}
	}
	return fmt.Sprintf("%d → %d [%s] Seq=%d Win=%d Len=%d",
		t.SrcPort, t.DstPort, strings.Join(ordered, ", "), t.Seq, t.Window, len(t.Payload))
}

func defaultInfo(p domain.Packet) string {
	if p.SrcPort != 0 || p.DstPort != 0 {
		return fmt.Sprintf("%s %d → %d", p.Proto, p.SrcPort, p.DstPort)
	}
	return fmt.Sprintf("%s %s → %s", p.Proto, p.Src, p.Dst)
}
