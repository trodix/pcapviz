// Package app holds the application core: use cases that orchestrate the domain
// through ports. It depends only on the domain and the port interfaces, never
// on a concrete adapter.
package app

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"pcapviz/internal/domain"
	"pcapviz/internal/port"
	"pcapviz/internal/tlsdecrypt"
)

// ErrNotFound is returned when a requested packet does not exist.
var ErrNotFound = errors.New("packet not found")

// Service wires the in-memory index and the packet decoder behind the use
// cases consumed by the driving (HTTP) adapter.
type Service struct {
	store   port.IndexStore
	decoder port.Decoder
	log     *slog.Logger
}

// New builds a Service from its outbound ports. A nil logger is replaced by a
// no-op logger.
func New(store port.IndexStore, decoder port.Decoder, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{store: store, decoder: decoder, log: logger}
}

// Load replaces the current capture with the packets produced by src.
func (s *Service) Load(src port.PacketSource) error {
	start := time.Now()
	s.store.Reset()
	if err := src.ForEach(func(p domain.Packet, raw []byte) error {
		s.store.Add(p, raw)
		return nil
	}); err != nil {
		s.log.Error("capture load failed", "error", err.Error(), "packetsSoFar", s.store.Count())
		return err
	}
	s.store.SetLinkType(src.LinkType())
	s.log.Info("capture loaded", "packets", s.store.Count(), "linkType", s.store.LinkType(), "took", time.Since(start).String())
	return nil
}

// Count returns the number of loaded packets.
func (s *Service) Count() int { return s.store.Count() }

// Page is the result of ListPackets.
type Page struct {
	Items  []domain.Packet `json:"items"`
	Total  int             `json:"total"`
	Offset int             `json:"offset"`
	Limit  int             `json:"limit"`
}

// ListPackets returns a filtered, paginated slice of packet summaries. An empty
// filter matches everything; an invalid filter returns an error.
func (s *Service) ListPackets(filter string, offset, limit int) (Page, error) {
	match := domain.MatchAll
	if filter != "" {
		f, err := domain.ParseFilter(filter)
		if err != nil {
			return Page{}, fmt.Errorf("invalid filter: %w", err)
		}
		match = f.Eval
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 100
	}
	items, total := s.store.Page(match, offset, limit)
	return Page{Items: items, Total: total, Offset: offset, Limit: limit}, nil
}

// PacketDetail decodes a single packet on demand.
func (s *Service) PacketDetail(num int) (domain.Detail, error) {
	raw, ok := s.store.Raw(num)
	if !ok {
		return domain.Detail{}, ErrNotFound
	}
	return s.decoder.Detail(raw, s.store.LinkType(), num)
}

// Stats computes the capture overview.
func (s *Service) Stats() domain.Stats {
	return domain.ComputeStats(s.store.All(), 60, 20)
}

// Conversations returns just the conversation list from the overview.
func (s *Service) Conversations() []domain.Conversation {
	return s.Stats().Conversations
}

// DecryptTLS reassembles the capture's TCP streams and decrypts the TLS 1.2
// sessions for which the SSLKEYLOGFILE provides the master secret.
func (s *Service) DecryptTLS(keylog []byte) []tlsdecrypt.Session {
	sessions := tlsdecrypt.Decrypt(s.store.Raws(), s.store.LinkType(), keylog)
	decrypted := 0
	for _, ss := range sessions {
		if ss.Decrypted {
			decrypted++
		}
	}
	s.log.Info("tls decrypt", "sessions", len(sessions), "decrypted", decrypted)
	return sessions
}
