// Command gensample writes a small, varied sample capture for manual testing.
// Temporary helper, not part of the shipped product.
package main

import (
	"log"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func main() {
	out := "sample.pcap"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	f, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		log.Fatal(err)
	}

	t := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	write := func(data []byte) {
		t = t.Add(120 * time.Millisecond)
		ci := gopacket.CaptureInfo{Timestamp: t, CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			log.Fatal(err)
		}
	}

	for i := 0; i < 3; i++ {
		write(dns())
		write(tcpSyn())
		write(httpGet())
		write(tlsHello())
		write(arp())
	}
	log.Printf("wrote %s", out)
}

func ser(ls ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

func eth(et layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: []byte{0, 0, 0, 0, 0, 1}, DstMAC: []byte{0, 0, 0, 0, 0, 2}, EthernetType: et}
}

func ip(proto layers.IPProtocol, dst []byte) *layers.IPv4 {
	return &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: []byte{10, 0, 0, 1}, DstIP: dst}
}

func dns() []byte {
	i := ip(layers.IPProtocolUDP, []byte{8, 8, 8, 8})
	u := &layers.UDP{SrcPort: 51000, DstPort: 53}
	u.SetNetworkLayerForChecksum(i)
	d := &layers.DNS{ID: 0x1234, Questions: []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	return ser(eth(layers.EthernetTypeIPv4), i, u, d)
}

func tcpSyn() []byte {
	i := ip(layers.IPProtocolTCP, []byte{1, 1, 1, 1})
	tc := &layers.TCP{SrcPort: 52000, DstPort: 443, SYN: true, Window: 64240, Seq: 1000}
	tc.SetNetworkLayerForChecksum(i)
	return ser(eth(layers.EthernetTypeIPv4), i, tc)
}

func httpGet() []byte {
	i := ip(layers.IPProtocolTCP, []byte{93, 184, 216, 34})
	tc := &layers.TCP{SrcPort: 53000, DstPort: 80, PSH: true, ACK: true, Window: 64240, Seq: 1}
	tc.SetNetworkLayerForChecksum(i)
	payload := gopacket.Payload([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	return ser(eth(layers.EthernetTypeIPv4), i, tc, payload)
}

func tlsHello() []byte {
	i := ip(layers.IPProtocolTCP, []byte{1, 1, 1, 1})
	tc := &layers.TCP{SrcPort: 54000, DstPort: 443, PSH: true, ACK: true, Window: 64240, Seq: 1}
	tc.SetNetworkLayerForChecksum(i)
	return ser(eth(layers.EthernetTypeIPv4), i, tc, gopacket.Payload(clientHello("secure.example.com")))
}

// clientHello builds a minimal TLS ClientHello carrying an SNI extension.
func clientHello(host string) []byte {
	sni := []byte(host)
	var serverName []byte
	serverName = append(serverName, 0x00)                                  // name_type host_name
	serverName = append(serverName, byte(len(sni)>>8), byte(len(sni)))     // name length
	serverName = append(serverName, sni...)                                //
	var snList []byte
	snList = append(snList, byte(len(serverName)>>8), byte(len(serverName)))
	snList = append(snList, serverName...)
	var ext []byte
	ext = append(ext, 0x00, 0x00)                                      // extension type server_name
	ext = append(ext, byte(len(snList)>>8), byte(len(snList)))         // extension length
	ext = append(ext, snList...)
	var exts []byte
	exts = append(exts, byte(len(ext)>>8), byte(len(ext)))
	exts = append(exts, ext...)

	var hs []byte
	hs = append(hs, 0x03, 0x03)                  // client_version TLS 1.2
	hs = append(hs, make([]byte, 32)...)         // random
	hs = append(hs, 0x00)                        // session_id len
	hs = append(hs, 0x00, 0x02, 0x13, 0x01)      // cipher_suites len + one suite
	hs = append(hs, 0x01, 0x00)                  // compression methods len + null
	hs = append(hs, exts...)                     // extensions

	body := append([]byte{0x01, byte(len(hs) >> 16), byte(len(hs) >> 8), byte(len(hs))}, hs...) // handshake header
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}, body...)     // record header
	return rec
}

func arp() []byte {
	a := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: []byte{0, 0, 0, 0, 0, 1}, SourceProtAddress: []byte{10, 0, 0, 1},
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte{10, 0, 0, 254},
	}
	return ser(eth(layers.EthernetTypeARP), a)
}
