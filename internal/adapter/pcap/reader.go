// Package pcap is the adapter that reads .pcap and .pcapng files using
// gopacket/pcapgo (pure Go, no libpcap). It implements two outbound ports:
// port.PacketSource (iterate + summarize packets) and port.Decoder (lazy,
// detailed per-packet decode).
package pcap

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"pcapviz/internal/domain"
)

// reader is the common subset of pcapgo's classic and pcapng readers.
type reader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// Source reads packets from a single capture file. Implements port.PacketSource.
type Source struct {
	path     string
	linkType int
}

// Open prepares a Source for the given .pcap/.pcapng file path. It validates
// that the file is a recognised capture format.
func Open(path string) (*Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if !isPcap(magic) && !isPcapng(magic) {
		return nil, fmt.Errorf("not a pcap/pcapng file (magic %x)", magic)
	}
	return &Source{path: path}, nil
}

// LinkType returns the capture link-layer type. It is only known after ForEach
// has opened the file; the application core reads it once loading completes.
func (s *Source) LinkType() int { return s.linkType }

// ForEach decodes every packet and calls fn with its summary and raw bytes.
func (s *Source) ForEach(fn func(domain.Packet, []byte) error) error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 1<<20)
	r, err := newReader(br)
	if err != nil {
		return err
	}
	lt := r.LinkType()
	s.linkType = int(lt)

	num := 0
	for {
		data, ci, err := r.ZeroCopyReadPacketData()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("packet %d: %w", num+1, err)
		}
		num++
		pkt := summarize(data, lt, num, ci)
		if err := fn(pkt, data); err != nil {
			return err
		}
	}
}

func newReader(br *bufio.Reader) (reader, error) {
	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("peek magic: %w", err)
	}
	if isPcapng(magic) {
		return pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
	}
	return pcapgo.NewReader(br)
}

func isPcap(b []byte) bool {
	switch {
	case b[0] == 0xa1 && b[1] == 0xb2 && b[2] == 0xc3 && b[3] == 0xd4: // microsecond, big-endian
		return true
	case b[0] == 0xd4 && b[1] == 0xc3 && b[2] == 0xb2 && b[3] == 0xa1: // microsecond, little-endian
		return true
	case b[0] == 0xa1 && b[1] == 0xb2 && b[2] == 0x3c && b[3] == 0x4d: // nanosecond, big-endian
		return true
	case b[0] == 0x4d && b[1] == 0x3c && b[2] == 0xb2 && b[3] == 0xa1: // nanosecond, little-endian
		return true
	}
	return false
}

func isPcapng(b []byte) bool {
	// pcapng Section Header Block type 0x0A0D0D0A.
	return b[0] == 0x0a && b[1] == 0x0d && b[2] == 0x0d && b[3] == 0x0a
}
