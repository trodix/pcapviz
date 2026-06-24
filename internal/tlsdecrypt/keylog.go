// Package tlsdecrypt decrypts TLS 1.2 application data captured in a pcap, using
// the session secrets from an SSLKEYLOGFILE (NSS key-log format). This is the
// standard, forward-secrecy-compatible method (the one Wireshark uses): the
// browser/curl writes the master secret keyed by the ClientHello random, and we
// derive the symmetric keys from it — so it works for ECDHE suites where the
// server's private key alone would be useless.
//
// Scope (v1): TLS 1.2 with AES-128/256-GCM cipher suites.
package tlsdecrypt

import (
	"encoding/hex"
	"strings"
)

// KeyLog maps a ClientHello random to its TLS 1.2 master secret.
type KeyLog struct {
	master map[[32]byte][]byte
}

// ParseKeyLog reads an SSLKEYLOGFILE. Only CLIENT_RANDOM lines (TLS 1.2) are
// used in this version; other line types (TLS 1.3 traffic secrets) are ignored.
func ParseKeyLog(data []byte) *KeyLog {
	kl := &KeyLog{master: map[[32]byte][]byte{}}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "CLIENT_RANDOM" {
			continue
		}
		cr, err := hex.DecodeString(fields[1])
		if err != nil || len(cr) != 32 {
			continue
		}
		ms, err := hex.DecodeString(fields[2])
		if err != nil || len(ms) != 48 {
			continue
		}
		var key [32]byte
		copy(key[:], cr)
		kl.master[key] = ms
	}
	return kl
}

// MasterSecret returns the master secret for a ClientHello random, if known.
func (k *KeyLog) MasterSecret(clientRandom [32]byte) ([]byte, bool) {
	ms, ok := k.master[clientRandom]
	return ms, ok
}

// Len reports how many CLIENT_RANDOM entries were parsed.
func (k *KeyLog) Len() int { return len(k.master) }
