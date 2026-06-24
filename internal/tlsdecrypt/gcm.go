package tlsdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// keyMaterial holds the per-direction AES-GCM keys and fixed IVs derived from
// the master secret.
type keyMaterial struct {
	clientKey, serverKey []byte
	clientIV, serverIV   []byte // 4-byte fixed nonces
}

// deriveKeys runs the TLS 1.2 key-expansion PRF to produce the write keys and
// fixed IVs (AEAD suites have no MAC keys).
func deriveKeys(master []byte, clientRandom, serverRandom [32]byte, suite suiteParams) keyMaterial {
	seed := append(append([]byte{}, serverRandom[:]...), clientRandom[:]...)
	need := 2*suite.keyLen + 2*fixedIVLen
	kb := prf12(master, "key expansion", seed, suite.newHash, need)

	k := suite.keyLen
	return keyMaterial{
		clientKey: kb[0:k],
		serverKey: kb[k : 2*k],
		clientIV:  kb[2*k : 2*k+fixedIVLen],
		serverIV:  kb[2*k+fixedIVLen : 2*k+2*fixedIVLen],
	}
}

// gcmCipher wraps an AES-GCM AEAD with its fixed IV and per-direction sequence.
type gcmCipher struct {
	aead    cipher.AEAD
	fixedIV []byte
	seq     uint64
}

func newGCM(key, fixedIV []byte) (*gcmCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &gcmCipher{aead: aead, fixedIV: fixedIV}, nil
}

// open decrypts one TLS 1.2 GCM record fragment (RFC 5246 + RFC 5288). The
// fragment is explicit_nonce(8) || ciphertext || tag(16). It advances the
// sequence number whether or not the record is application data.
func (g *gcmCipher) open(contentType uint8, version uint16, fragment []byte) ([]byte, error) {
	seq := g.seq
	g.seq++

	if len(fragment) < explicitNL+gcmTagLen {
		return nil, fmt.Errorf("record too short")
	}
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, g.fixedIV...)
	nonce = append(nonce, fragment[:explicitNL]...)
	ciphertext := fragment[explicitNL:] // includes the trailing tag

	plainLen := len(ciphertext) - gcmTagLen
	aad := make([]byte, 13)
	binary.BigEndian.PutUint64(aad[0:8], seq)
	aad[8] = contentType
	binary.BigEndian.PutUint16(aad[9:11], version)
	binary.BigEndian.PutUint16(aad[11:13], uint16(plainLen))

	return g.aead.Open(nil, nonce, ciphertext, aad)
}
