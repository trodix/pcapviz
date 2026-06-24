package tlsdecrypt

import (
	"crypto/hmac"
	"hash"
)

// prf12 is the TLS 1.2 pseudo-random function (RFC 5246 §5): P_hash applied to
// label||seed. It expands to outLen bytes.
func prf12(secret []byte, label string, seed []byte, newHash func() hash.Hash, outLen int) []byte {
	labelSeed := append([]byte(label), seed...)
	out := make([]byte, 0, outLen)

	// A(0) = labelSeed; A(i) = HMAC(secret, A(i-1)).
	a := labelSeed
	for len(out) < outLen {
		a = hmacSum(secret, a, newHash)
		out = append(out, hmacSum(secret, append(append([]byte{}, a...), labelSeed...), newHash)...)
	}
	return out[:outLen]
}

func hmacSum(key, data []byte, newHash func() hash.Hash) []byte {
	m := hmac.New(newHash, key)
	m.Write(data)
	return m.Sum(nil)
}
