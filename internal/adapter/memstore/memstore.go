// Package memstore is an in-memory adapter implementing port.IndexStore.
// It targets the v1 scope (captures under ~100 MB): the whole capture — packet
// summaries plus raw bytes for lazy detail decoding — is held in RAM. Swapping
// to a disk-backed/streaming store later means adding a new adapter without
// touching the domain or the application core.
package memstore

import (
	"sync"

	"pcapviz/internal/domain"
)

type entry struct {
	pkt domain.Packet
	raw []byte
}

// Store is a concurrency-safe in-memory index of a single loaded capture.
type Store struct {
	mu       sync.RWMutex
	entries  []entry
	linkType int
}

// New returns an empty store.
func New() *Store { return &Store{} }

func (s *Store) SetLinkType(lt int) {
	s.mu.Lock()
	s.linkType = lt
	s.mu.Unlock()
}

func (s *Store) LinkType() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.linkType
}

func (s *Store) Add(pkt domain.Packet, raw []byte) {
	// Copy raw: gopacket's zero-copy reader reuses its buffer between packets.
	cp := make([]byte, len(raw))
	copy(cp, raw)
	s.mu.Lock()
	s.entries = append(s.entries, entry{pkt: pkt, raw: cp})
	s.mu.Unlock()
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *Store) All() []domain.Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Packet, len(s.entries))
	for i := range s.entries {
		out[i] = s.entries[i].pkt
	}
	return out
}

func (s *Store) Page(match func(domain.Packet) bool, offset, limit int) ([]domain.Packet, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if match == nil {
		match = domain.MatchAll
	}
	var items []domain.Packet
	total := 0
	for i := range s.entries {
		p := s.entries[i].pkt
		if !match(p) {
			continue
		}
		if total >= offset && (limit <= 0 || len(items) < limit) {
			items = append(items, p)
		}
		total++
	}
	return items, total
}

func (s *Store) Raw(num int) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Packets are appended in order, so num maps to index num-1, but guard
	// against gaps by checking the stored number.
	if num >= 1 && num <= len(s.entries) && s.entries[num-1].pkt.Num == num {
		return s.entries[num-1].raw, true
	}
	for i := range s.entries {
		if s.entries[i].pkt.Num == num {
			return s.entries[i].raw, true
		}
	}
	return nil, false
}

func (s *Store) Raws() [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([][]byte, len(s.entries))
	for i := range s.entries {
		out[i] = s.entries[i].raw
	}
	return out
}

func (s *Store) Reset() {
	s.mu.Lock()
	s.entries = nil
	s.linkType = 0
	s.mu.Unlock()
}
