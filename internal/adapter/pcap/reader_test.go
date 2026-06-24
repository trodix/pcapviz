package pcap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"pcapviz/internal/domain"
)

// writeTestPcap crafts a small capture (a DNS query and a TCP SYN) and returns
// its path.
func writeTestPcap(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	for _, data := range [][]byte{dnsQueryPacket(t), tcpSynPacket(t)} {
		ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dnsQueryPacket(t *testing.T) []byte {
	eth := &layers.Ethernet{
		SrcMAC: hw(1), DstMAC: hw(2), EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{8, 8, 8, 8}}
	udp := &layers.UDP{SrcPort: 51000, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{ID: 0x1234, Questions: []layers.DNSQuestion{
		{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
	}}
	return serialize(t, eth, ip, udp, dns)
}

func tcpSynPacket(t *testing.T) []byte {
	eth := &layers.Ethernet{SrcMAC: hw(1), DstMAC: hw(2), EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{1, 1, 1, 1}}
	tcp := &layers.TCP{SrcPort: 52000, DstPort: 443, SYN: true, Window: 64240, Seq: 1000}
	tcp.SetNetworkLayerForChecksum(ip)
	return serialize(t, eth, ip, tcp)
}

func hw(n byte) []byte { return []byte{0, 0, 0, 0, 0, n} }

func TestSourceForEach(t *testing.T) {
	path := writeTestPcap(t)
	src, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var pkts []domain.Packet
	var raws [][]byte
	if err := src.ForEach(func(p domain.Packet, raw []byte) error {
		pkts = append(pkts, p)
		cp := make([]byte, len(raw))
		copy(cp, raw)
		raws = append(raws, cp)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2", len(pkts))
	}

	dns := pkts[0]
	if dns.Proto != "DNS" || dns.DstPort != 53 || dns.Src != "10.0.0.1" {
		t.Errorf("dns summary wrong: %+v", dns)
	}
	if dns.App == nil || dns.App.DNSName != "example.com" {
		t.Errorf("dns name not extracted: %+v", dns.App)
	}

	syn := pkts[1]
	if syn.Proto != "TCP" || syn.DstPort != 443 {
		t.Errorf("tcp summary wrong: %+v", syn)
	}

	if src.LinkType() != int(layers.LinkTypeEthernet) {
		t.Errorf("link type = %d", src.LinkType())
	}

	// detail decode of the DNS packet
	d, err := NewDecoder().Detail(raws[0], src.LinkType(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var hasEth, hasIP, hasDNS bool
	for _, l := range d.Layers {
		switch l.Name {
		case "Ethernet":
			hasEth = true
		case "IPv4":
			hasIP = true
		case "DNS":
			hasDNS = true
		}
	}
	if !hasEth || !hasIP || !hasDNS {
		t.Errorf("detail layers incomplete: %+v", d.Layers)
	}
	if d.HexDump == "" {
		t.Error("hex dump empty")
	}
}
