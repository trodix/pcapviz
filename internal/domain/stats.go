package domain

import (
	"sort"
	"time"
)

// ProtoCount aggregates packets/bytes for one protocol.
type ProtoCount struct {
	Proto   string `json:"proto"`
	Packets int    `json:"packets"`
	Bytes   int    `json:"bytes"`
}

// Talker aggregates traffic for one endpoint address.
type Talker struct {
	Addr    string `json:"addr"`
	Packets int    `json:"packets"`
	Bytes   int    `json:"bytes"`
}

// Conversation aggregates traffic exchanged between two endpoints.
type Conversation struct {
	A       string `json:"a"`
	B       string `json:"b"`
	Proto   string `json:"proto"`
	Packets int    `json:"packets"`
	Bytes   int    `json:"bytes"`
}

// TimeBucket is one point of the traffic timeline.
type TimeBucket struct {
	Time    time.Time `json:"time"`
	Packets int       `json:"packets"`
	Bytes   int       `json:"bytes"`
}

// Stats is the computed overview of a capture.
type Stats struct {
	TotalPackets  int            `json:"totalPackets"`
	TotalBytes    int            `json:"totalBytes"`
	Start         time.Time      `json:"start"`
	End           time.Time      `json:"end"`
	Protocols     []ProtoCount   `json:"protocols"`
	TopTalkers    []Talker       `json:"topTalkers"`
	Conversations []Conversation `json:"conversations"`
	Timeline      []TimeBucket   `json:"timeline"`
}

// ComputeStats aggregates a slice of packet summaries into an overview.
// buckets controls how many timeline points are produced (the capture duration
// is split into that many equal slices). topN caps the talkers/conversations
// lists; pass 0 for sensible defaults.
func ComputeStats(packets []Packet, buckets, topN int) Stats {
	if topN <= 0 {
		topN = 20
	}
	if buckets <= 0 {
		buckets = 60
	}
	var s Stats
	if len(packets) == 0 {
		return s
	}

	protos := map[string]*ProtoCount{}
	talkers := map[string]*Talker{}
	convs := map[string]*Conversation{}
	start, end := packets[0].Time, packets[0].Time

	for _, p := range packets {
		s.TotalPackets++
		s.TotalBytes += p.Length
		if p.Time.Before(start) {
			start = p.Time
		}
		if p.Time.After(end) {
			end = p.Time
		}

		pc := protos[p.Proto]
		if pc == nil {
			pc = &ProtoCount{Proto: p.Proto}
			protos[p.Proto] = pc
		}
		pc.Packets++
		pc.Bytes += p.Length

		addTalker(talkers, p.Src, p.Length)
		addTalker(talkers, p.Dst, p.Length)

		a := Endpoint(p.Src, p.SrcPort)
		b := Endpoint(p.Dst, p.DstPort)
		key, ca, cb := convKey(a, b)
		cv := convs[key+"|"+p.Proto]
		if cv == nil {
			cv = &Conversation{A: ca, B: cb, Proto: p.Proto}
			convs[key+"|"+p.Proto] = cv
		}
		cv.Packets++
		cv.Bytes += p.Length
	}

	s.Start, s.End = start, end
	s.Protocols = sortedProtos(protos)
	s.TopTalkers = topTalkers(talkers, topN)
	s.Conversations = topConversations(convs, topN)
	s.Timeline = timeline(packets, start, end, buckets)
	return s
}

func addTalker(m map[string]*Talker, addr string, n int) {
	t := m[addr]
	if t == nil {
		t = &Talker{Addr: addr}
		m[addr] = t
	}
	t.Packets++
	t.Bytes += n
}

// convKey returns a stable, direction-independent key plus the ordered pair.
func convKey(a, b string) (key, first, second string) {
	if a <= b {
		return a + "|" + b, a, b
	}
	return b + "|" + a, b, a
}

func sortedProtos(m map[string]*ProtoCount) []ProtoCount {
	out := make([]ProtoCount, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func topTalkers(m map[string]*Talker, n int) []Talker {
	out := make([]Talker, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Addr < out[j].Addr
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topConversations(m map[string]*Conversation, n int) []Conversation {
	out := make([]Conversation, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].A < out[j].A
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func timeline(packets []Packet, start, end time.Time, buckets int) []TimeBucket {
	span := end.Sub(start)
	if span <= 0 {
		// single instant: one bucket with everything
		var tot, by int
		for _, p := range packets {
			tot++
			by += p.Length
		}
		return []TimeBucket{{Time: start, Packets: tot, Bytes: by}}
	}
	step := span / time.Duration(buckets)
	if step <= 0 {
		step = time.Nanosecond
	}
	out := make([]TimeBucket, buckets)
	for i := range out {
		out[i].Time = start.Add(time.Duration(i) * step)
	}
	for _, p := range packets {
		idx := int(p.Time.Sub(start) / step)
		if idx < 0 {
			idx = 0
		}
		if idx >= buckets {
			idx = buckets - 1
		}
		out[idx].Packets++
		out[idx].Bytes += p.Length
	}
	return out
}
