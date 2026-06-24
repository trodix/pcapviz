package tlsdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
)

var errNoContentType = errors.New("tls13: decrypted record has no content type")

const tls13IVLen = 12

// tls13Suite describes a supported TLS 1.3 AES-GCM cipher suite.
type tls13Suite struct {
	name    string
	keyLen  int
	newHash func() hash.Hash
}

var tls13Suites = map[uint16]tls13Suite{
	0x1301: {"TLS_AES_128_GCM_SHA256", 16, sha256.New},
	0x1302: {"TLS_AES_256_GCM_SHA384", 32, sha512.New384},
}

func is13Suite(id uint16) bool { _, ok := tls13Suites[id]; return ok }

// tls13Cipher decrypts records protected by one TLS 1.3 traffic secret.
type tls13Cipher struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

// newTLS13Cipher derives the record key and IV from a traffic secret
// (RFC 8446 §7.3).
func newTLS13Cipher(secret []byte, s tls13Suite) (*tls13Cipher, error) {
	key := hkdfExpandLabel(s.newHash, secret, "key", nil, s.keyLen)
	iv := hkdfExpandLabel(s.newHash, secret, "iv", nil, tls13IVLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &tls13Cipher{aead: aead, iv: iv}, nil
}

// open decrypts one TLS 1.3 record. header is the 5-byte record header (the
// AEAD additional data); fragment is the encrypted_record (ciphertext||tag). It
// returns the inner plaintext and its real content type (the trailing non-zero
// byte), advancing the sequence number.
func (c *tls13Cipher) open(header, fragment []byte) (content []byte, innerType uint8, err error) {
	nonce := make([]byte, tls13IVLen)
	copy(nonce, c.iv)
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], c.seq)
	for i := 0; i < 8; i++ {
		nonce[tls13IVLen-8+i] ^= sb[i]
	}
	c.seq++

	plain, err := c.aead.Open(nil, nonce, fragment, header)
	if err != nil {
		return nil, 0, err
	}
	// Strip zero padding; the last non-zero byte is the real content type.
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0, errNoContentType
	}
	return plain[:i], plain[i], nil
}

// decryptStreams13 decrypts a TLS 1.3 connection using the handshake and
// application traffic secrets from the key log.
func decryptStreams13(s *Session, cRecs, sRecs []tlsRecord, suiteID uint16, sec *secrets) {
	suite := tls13Suites[suiteID]

	clientData, ok1 := decryptDirection13(cRecs, suite, sec.clientHandshake, sec.clientApp)
	serverData, ok2 := decryptDirection13(sRecs, suite, sec.serverHandshake, sec.serverApp)
	if !ok1 || !ok2 {
		s.Note = "missing TLS 1.3 traffic secrets in the key log"
		return
	}
	s.ClientData = clientData
	s.ServerData = serverData
	s.Decrypted = true
}

// decryptDirection13 walks one direction's records: encrypted records start
// under the handshake secret; after the encrypted Finished, the application
// secret takes over (each secret has its own sequence number starting at 0).
func decryptDirection13(recs []tlsRecord, suite tls13Suite, hsSecret, appSecret []byte) ([]byte, bool) {
	if len(hsSecret) == 0 || len(appSecret) == 0 {
		return nil, false
	}
	hs, err1 := newTLS13Cipher(hsSecret, suite)
	app, err2 := newTLS13Cipher(appSecret, suite)
	if err1 != nil || err2 != nil {
		return nil, false
	}

	var data []byte
	var hsBuf []byte
	inHandshake := true
	for _, r := range recs {
		if r.contentType != recAppData {
			continue // plaintext ClientHello/ServerHello/ChangeCipherSpec
		}
		header := []byte{r.contentType, byte(r.version >> 8), byte(r.version), byte(len(r.fragment) >> 8), byte(len(r.fragment))}

		cph := app
		if inHandshake {
			cph = hs
		}
		content, innerType, err := cph.open(header, r.fragment)
		if err != nil {
			break // desynchronized; stop this direction
		}

		switch innerType {
		case recHandshake:
			if inHandshake {
				hsBuf = append(hsBuf, content...)
				if hasFinished(hsBuf) {
					inHandshake = false // application secret from the next record
				}
			}
		case recAppData:
			data = append(data, content...)
		}
	}
	return data, true
}

const hsFinished = 20

func hasFinished(buf []byte) bool {
	for _, m := range parseHandshake(buf) {
		if m.msgType == hsFinished {
			return true
		}
	}
	return false
}
