package tlsdecrypt

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// TLS record content types.
const (
	recCCS       = 20
	recAlert     = 21
	recHandshake = 22
	recAppData   = 23
)

// tlsRecord is one TLS record from a byte stream.
type tlsRecord struct {
	contentType uint8
	version     uint16
	fragment    []byte
}

// parseRecords splits a (plaintext-framed) TLS byte stream into records. A
// trailing truncated record is ignored.
func parseRecords(stream []byte) []tlsRecord {
	var recs []tlsRecord
	for len(stream) >= 5 {
		ct := stream[0]
		ver := binary.BigEndian.Uint16(stream[1:3])
		ln := int(binary.BigEndian.Uint16(stream[3:5]))
		if 5+ln > len(stream) {
			break
		}
		recs = append(recs, tlsRecord{contentType: ct, version: ver, fragment: stream[5 : 5+ln]})
		stream = stream[5+ln:]
	}
	return recs
}

// handshakeMsg is one handshake message (may span/share records).
type handshakeMsg struct {
	msgType uint8
	body    []byte
}

// parseHandshake splits concatenated handshake-record fragments into messages.
func parseHandshake(buf []byte) []handshakeMsg {
	var msgs []handshakeMsg
	for len(buf) >= 4 {
		mt := buf[0]
		ln := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if 4+ln > len(buf) {
			break
		}
		msgs = append(msgs, handshakeMsg{msgType: mt, body: buf[4 : 4+ln]})
		buf = buf[4+ln:]
	}
	return msgs
}

const (
	hsClientHello = 1
	hsServerHello = 2
)

// clientRandom extracts the 32-byte random from a ClientHello body.
func clientRandom(body []byte) ([32]byte, bool) {
	var r [32]byte
	if len(body) < 2+32 { // client_version(2) + random(32)
		return r, false
	}
	copy(r[:], body[2:34])
	return r, true
}

// serverHelloInfo extracts server_random and the negotiated cipher suite.
func serverHelloInfo(body []byte) (random [32]byte, suite uint16, ok bool) {
	if len(body) < 2+32+1 {
		return random, 0, false
	}
	copy(random[:], body[2:34])
	p := body[34:]
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return random, 0, false
	}
	p = p[sidLen:]
	suite = binary.BigEndian.Uint16(p[0:2])
	return random, suite, true
}

// suiteParams describes a supported AES-GCM cipher suite.
type suiteParams struct {
	name    string
	keyLen  int // AES key length
	newHash func() hash.Hash
}

const (
	fixedIVLen = 4  // TLS 1.2 GCM implicit nonce ("salt")
	explicitNL = 8  // per-record explicit nonce
	gcmTagLen  = 16 // GCM auth tag
)

// gcmSuites maps the supported TLS 1.2 AES-GCM suites to their parameters. The
// key-exchange part (ECDHE/RSA/DHE/ECDSA) is irrelevant here because the master
// secret comes from the key log.
var gcmSuites = map[uint16]suiteParams{
	0xc02f: {"ECDHE_RSA_AES_128_GCM_SHA256", 16, sha256.New},
	0xc02b: {"ECDHE_ECDSA_AES_128_GCM_SHA256", 16, sha256.New},
	0x009c: {"RSA_AES_128_GCM_SHA256", 16, sha256.New},
	0x009e: {"DHE_RSA_AES_128_GCM_SHA256", 16, sha256.New},
	0xc030: {"ECDHE_RSA_AES_256_GCM_SHA384", 32, sha512.New384},
	0xc02c: {"ECDHE_ECDSA_AES_256_GCM_SHA384", 32, sha512.New384},
	0x009d: {"RSA_AES_256_GCM_SHA384", 32, sha512.New384},
	0x009f: {"DHE_RSA_AES_256_GCM_SHA384", 32, sha512.New384},
}

func isGCMSuite(id uint16) bool { _, ok := gcmSuites[id]; return ok }

func suiteName(id uint16) string {
	if s, ok := gcmSuites[id]; ok {
		return s.name
	}
	if s, ok := tls13Suites[id]; ok {
		return s.name
	}
	return fmt.Sprintf("0x%04x", id)
}
