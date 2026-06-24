package tlsdecrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// teeConn records everything written to (out) and read from (in) the wrapped
// connection — i.e. the two raw TLS byte streams.
type teeConn struct {
	net.Conn
	out, in *bytes.Buffer
}

func (t *teeConn) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	t.out.Write(p[:n])
	return n, err
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.in.Write(p[:n])
	return n, err
}

const reqText = "GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n"
const respText = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nHello decrypted!"

// tlsExchange performs a real TLS 1.2 handshake + data exchange with the given
// cipher suite, returning the two raw streams and the key log.
func tlsExchange(t *testing.T, suite uint16) (clientStream, serverStream, keylog []byte) {
	return exchange(t, tls.VersionTLS12, []uint16{suite})
}

// tls13Exchange performs a real TLS 1.3 exchange (Go selects the suite).
func tls13Exchange(t *testing.T) (clientStream, serverStream, keylog []byte) {
	return exchange(t, tls.VersionTLS13, nil)
}

func exchange(t *testing.T, version uint16, suites []uint16) (clientStream, serverStream, keylog []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	var klBuf bytes.Buffer
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   version,
		MaxVersion:   version,
		CipherSuites: suites,
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       suites,
		KeyLogWriter:       &klBuf,
	}

	c1, c2 := net.Pipe()
	tee := &teeConn{Conn: c1, out: &bytes.Buffer{}, in: &bytes.Buffer{}}

	done := make(chan error, 1)
	go func() {
		srv := tls.Server(c2, serverCfg)
		if err := srv.Handshake(); err != nil {
			done <- err
			return
		}
		buf := make([]byte, len(reqText))
		if _, err := srv.Read(buf); err != nil {
			done <- err
			return
		}
		if _, err := srv.Write([]byte(respText)); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	cli := tls.Client(tee, clientCfg)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := cli.Write([]byte(reqText)); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, len(respText))
	if _, err := cli.Read(resp); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}

	return tee.out.Bytes(), tee.in.Bytes(), klBuf.Bytes()
}

func TestDecryptStreams(t *testing.T) {
	for _, suite := range []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	} {
		cStream, sStream, keylog := tlsExchange(t, suite)
		s := decryptStreams(cStream, sStream, ParseKeyLog(keylog))
		if !s.Decrypted {
			t.Fatalf("suite 0x%04x: not decrypted: %s", suite, s.Note)
		}
		if !strings.Contains(string(s.ClientData), "GET /secret") {
			t.Errorf("suite 0x%04x: client data = %q", suite, s.ClientData)
		}
		if !strings.Contains(string(s.ServerData), "Hello decrypted!") {
			t.Errorf("suite 0x%04x: server data = %q", suite, s.ServerData)
		}
	}
}

func TestDecryptStreams13(t *testing.T) {
	cStream, sStream, keylog := tls13Exchange(t)
	s := decryptStreams(cStream, sStream, ParseKeyLog(keylog))
	if !s.Decrypted {
		t.Fatalf("TLS 1.3 not decrypted: %s (suite %s)", s.Note, s.CipherSuite)
	}
	if s.Version != "TLS 1.3" {
		t.Errorf("version = %q", s.Version)
	}
	if !strings.Contains(string(s.ClientData), "GET /secret") {
		t.Errorf("client data = %q", s.ClientData)
	}
	if !strings.Contains(string(s.ServerData), "Hello decrypted!") {
		t.Errorf("server data = %q", s.ServerData)
	}
}

func TestDecryptFromPcap(t *testing.T) {
	cStream, sStream, keylog := tlsExchange(t, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	client := endpointPair{ip: []byte{10, 0, 0, 1}, port: 50000}
	server := endpointPair{ip: []byte{93, 184, 216, 34}, port: 443}
	var frames [][]byte
	frames = append(frames, tcpFrames(t, client, server, 1000, cStream)...)
	frames = append(frames, tcpFrames(t, server, client, 5000, sStream)...)

	sessions := Decrypt(frames, int(layers.LinkTypeEthernet), keylog)
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions))
	}
	s := sessions[0]
	if !s.Decrypted {
		t.Fatalf("not decrypted: %s", s.Note)
	}
	if s.Client != "10.0.0.1:50000" || s.Server != "93.184.216.34:443" {
		t.Errorf("endpoints: client=%s server=%s", s.Client, s.Server)
	}
	if !strings.Contains(string(s.ClientData), "GET /secret") ||
		!strings.Contains(string(s.ServerData), "Hello decrypted!") {
		t.Errorf("decrypted data mismatch: client=%q server=%q", s.ClientData, s.ServerData)
	}
	if s.Version != "TLS 1.2" {
		t.Errorf("version = %q", s.Version)
	}
}

type endpointPair struct {
	ip   []byte
	port int
}

// tcpFrames chops a stream into Ethernet/IPv4/TCP packets with incrementing
// sequence numbers.
func tcpFrames(t *testing.T, src, dst endpointPair, baseSeq uint32, stream []byte) [][]byte {
	t.Helper()
	const mss = 1300
	var frames [][]byte
	for off := 0; off < len(stream); off += mss {
		end := off + mss
		if end > len(stream) {
			end = len(stream)
		}
		eth := &layers.Ethernet{
			SrcMAC: []byte{0, 0, 0, 0, 0, 1}, DstMAC: []byte{0, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: src.ip, DstIP: dst.ip,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(src.port), DstPort: layers.TCPPort(dst.port),
			Seq: baseSeq + uint32(off), ACK: true, Window: 64240,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(stream[off:end])); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, buf.Bytes())
	}
	return frames
}
