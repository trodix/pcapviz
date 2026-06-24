package http

import (
	"io"
	"net/http"

	"pcapviz/internal/tlsdecrypt"
)

// maxTextPreview caps how much decrypted data is sent per direction.
const maxTextPreview = 256 * 1024

type tlsSessionDTO struct {
	Client      string `json:"client"`
	Server      string `json:"server"`
	Version     string `json:"version"`
	CipherSuite string `json:"cipherSuite"`
	Decrypted   bool   `json:"decrypted"`
	Note        string `json:"note,omitempty"`
	ClientBytes int    `json:"clientBytes"`
	ServerBytes int    `json:"serverBytes"`
	ClientText  string `json:"clientText,omitempty"`
	ServerText  string `json:"serverText,omitempty"`
}

// tlsDecrypt accepts an SSLKEYLOGFILE (raw text body) and returns the decrypted
// TLS sessions of the loaded capture.
func (h *Handler) tlsDecrypt(w http.ResponseWriter, r *http.Request) {
	keylog, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sessions := h.svc.DecryptTLS(keylog)

	dtos := make([]tlsSessionDTO, 0, len(sessions))
	for _, s := range sessions {
		dtos = append(dtos, toDTO(s))
	}
	writeJSON(w, http.StatusOK, dtos)
}

func toDTO(s tlsdecrypt.Session) tlsSessionDTO {
	return tlsSessionDTO{
		Client:      s.Client,
		Server:      s.Server,
		Version:     s.Version,
		CipherSuite: s.CipherSuite,
		Decrypted:   s.Decrypted,
		Note:        s.Note,
		ClientBytes: len(s.ClientData),
		ServerBytes: len(s.ServerData),
		ClientText:  preview(s.ClientData),
		ServerText:  preview(s.ServerData),
	}
}

func preview(b []byte) string {
	if len(b) > maxTextPreview {
		b = b[:maxTextPreview]
	}
	return string(b)
}
