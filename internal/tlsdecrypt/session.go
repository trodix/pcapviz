package tlsdecrypt

import "encoding/binary"

// Session is the result of attempting to decrypt one TLS connection.
type Session struct {
	Client      string `json:"client"` // ip:port that sent the ClientHello
	Server      string `json:"server"`
	Version     string `json:"version"`
	CipherSuite string `json:"cipherSuite"`
	Decrypted   bool   `json:"decrypted"`
	Note        string `json:"note,omitempty"` // why not decrypted, when applicable

	// Decrypted application data per direction.
	ClientData []byte `json:"-"`
	ServerData []byte `json:"-"`
}

// decryptStreams attempts to decrypt one connection given the two reassembled
// directions (client→server and server→client byte streams) and the key log.
func decryptStreams(clientStream, serverStream []byte, kl *KeyLog) Session {
	var s Session

	cRecs := parseRecords(clientStream)
	sRecs := parseRecords(serverStream)

	// Client random from the ClientHello.
	var cRandom [32]byte
	if hs := handshakeBefore(cRecs); hs != nil {
		for _, m := range parseHandshake(hs) {
			if m.msgType == hsClientHello {
				if r, ok := clientRandom(m.body); ok {
					cRandom = r
				}
			}
		}
	}

	// Server random + cipher suite + negotiated version from the ServerHello.
	var sRandom [32]byte
	var suiteID uint16
	if hs := handshakeBefore(sRecs); hs != nil {
		for _, m := range parseHandshake(hs) {
			if m.msgType == hsServerHello {
				r, suite, ok := serverHelloInfo(m.body)
				if ok {
					sRandom, suiteID = r, suite
					if len(m.body) >= 2 {
						s.Version = versionName(binary.BigEndian.Uint16(m.body[0:2]))
					}
				}
			}
		}
	}
	s.CipherSuite = suiteName(suiteID)

	suite, ok := gcmSuites[suiteID]
	if !ok {
		s.Note = "unsupported cipher suite (only TLS 1.2 AES-GCM is supported)"
		return s
	}

	master, ok := kl.MasterSecret(cRandom)
	if !ok {
		s.Note = "no matching CLIENT_RANDOM in the key log"
		return s
	}

	km := deriveKeys(master, cRandom, sRandom, suite)
	cGCM, err1 := newGCM(km.clientKey, km.clientIV)
	sGCM, err2 := newGCM(km.serverKey, km.serverIV)
	if err1 != nil || err2 != nil {
		s.Note = "key setup failed"
		return s
	}

	s.ClientData = decryptDirection(cRecs, cGCM)
	s.ServerData = decryptDirection(sRecs, sGCM)
	s.Decrypted = true
	return s
}

// handshakeBefore concatenates the plaintext handshake fragments that appear
// before the ChangeCipherSpec record.
func handshakeBefore(recs []tlsRecord) []byte {
	var buf []byte
	for _, r := range recs {
		if r.contentType == recCCS {
			break
		}
		if r.contentType == recHandshake {
			buf = append(buf, r.fragment...)
		}
	}
	return buf
}

// decryptDirection decrypts the encrypted records that follow ChangeCipherSpec,
// returning the concatenated application-data plaintext.
func decryptDirection(recs []tlsRecord, g *gcmCipher) []byte {
	var data []byte
	encrypting := false
	for _, r := range recs {
		if !encrypting {
			if r.contentType == recCCS {
				encrypting = true // subsequent records use the cipher, seq from 0
			}
			continue
		}
		plain, err := g.open(r.contentType, r.version, r.fragment)
		if err != nil {
			// A failure desynchronizes the sequence counter; stop this side.
			break
		}
		if r.contentType == recAppData {
			data = append(data, plain...)
		}
	}
	return data
}

func versionName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return "unknown"
}
