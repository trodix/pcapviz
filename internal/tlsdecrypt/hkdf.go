package tlsdecrypt

import (
	"crypto/hmac"
	"hash"
)

// hkdfExpand is HKDF-Expand (RFC 5869 §2.3).
func hkdfExpand(newHash func() hash.Hash, prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	for i := 1; len(out) < length; i++ {
		h := hmac.New(newHash, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{byte(i)})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// hkdfExpandLabel is the TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
func hkdfExpandLabel(newHash func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 4+len(fullLabel)+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(newHash, secret, info, length)
}
