// Package tlsdecrypt decrypts TLS application data captured in a pcap, using the
// session secrets from an SSLKEYLOGFILE (NSS key-log format). This is the
// standard, forward-secrecy-compatible method (the one Wireshark uses): the
// browser/curl writes the secrets keyed by the ClientHello random, and we derive
// the symmetric keys from them — so it works for ECDHE suites where the server's
// private key alone would be useless.
//
// Scope: TLS 1.2 (AES-GCM, via the master secret) and TLS 1.3 (AES-GCM, via the
// handshake/application traffic secrets).
package tlsdecrypt

import (
	"encoding/hex"
	"strings"
)

// secrets holds the key-log material for one connection (keyed by ClientHello
// random). Only the fields relevant to the negotiated version are populated.
type secrets struct {
	master []byte // TLS 1.2: master secret

	clientHandshake []byte // TLS 1.3 traffic secrets
	serverHandshake []byte
	clientApp       []byte
	serverApp       []byte
}

// KeyLog maps a ClientHello random to its session secrets.
type KeyLog struct {
	byRandom map[[32]byte]*secrets
}

// ParseKeyLog reads an SSLKEYLOGFILE (TLS 1.2 CLIENT_RANDOM and TLS 1.3 traffic
// secret lines).
func ParseKeyLog(data []byte) *KeyLog {
	kl := &KeyLog{byRandom: map[[32]byte]*secrets{}}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		cr, err := hex.DecodeString(f[1])
		if err != nil || len(cr) != 32 {
			continue
		}
		val, err := hex.DecodeString(f[2])
		if err != nil {
			continue
		}
		var key [32]byte
		copy(key[:], cr)
		s := kl.byRandom[key]
		if s == nil {
			s = &secrets{}
			kl.byRandom[key] = s
		}
		switch f[0] {
		case "CLIENT_RANDOM":
			s.master = val
		case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
			s.clientHandshake = val
		case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
			s.serverHandshake = val
		case "CLIENT_TRAFFIC_SECRET_0":
			s.clientApp = val
		case "SERVER_TRAFFIC_SECRET_0":
			s.serverApp = val
		}
	}
	return kl
}

func (k *KeyLog) secretsFor(clientRandom [32]byte) (*secrets, bool) {
	s, ok := k.byRandom[clientRandom]
	return s, ok
}

// Len reports how many connections have key material.
func (k *KeyLog) Len() int { return len(k.byRandom) }
