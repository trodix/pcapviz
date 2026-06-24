package domain

import (
	"testing"
	"time"
)

func TestComputeStats(t *testing.T) {
	base := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	packets := []Packet{
		{Num: 1, Time: base, Src: "10.0.0.1", Dst: "8.8.8.8", SrcPort: 51000, DstPort: 53, Proto: "DNS", Length: 74},
		{Num: 2, Time: base.Add(time.Second), Src: "8.8.8.8", Dst: "10.0.0.1", SrcPort: 53, DstPort: 51000, Proto: "DNS", Length: 90},
		{Num: 3, Time: base.Add(2 * time.Second), Src: "10.0.0.1", Dst: "1.1.1.1", SrcPort: 52000, DstPort: 443, Proto: "TLS", Length: 200},
	}
	s := ComputeStats(packets, 10, 5)

	if s.TotalPackets != 3 {
		t.Errorf("TotalPackets = %d, want 3", s.TotalPackets)
	}
	if s.TotalBytes != 364 {
		t.Errorf("TotalBytes = %d, want 364", s.TotalBytes)
	}
	if !s.Start.Equal(base) || !s.End.Equal(base.Add(2*time.Second)) {
		t.Errorf("Start/End = %v/%v", s.Start, s.End)
	}
	if len(s.Protocols) != 2 || s.Protocols[0].Proto != "DNS" || s.Protocols[0].Packets != 2 {
		t.Errorf("Protocols = %+v", s.Protocols)
	}
	// 10.0.0.1 appears in all 3 packets -> top talker
	if len(s.TopTalkers) == 0 || s.TopTalkers[0].Addr != "10.0.0.1" {
		t.Errorf("TopTalkers[0] = %+v", s.TopTalkers)
	}
	// DNS exchange between the two endpoints is one conversation (both directions merged)
	var dnsConv *Conversation
	for i := range s.Conversations {
		if s.Conversations[i].Proto == "DNS" {
			dnsConv = &s.Conversations[i]
		}
	}
	if dnsConv == nil || dnsConv.Packets != 2 {
		t.Errorf("DNS conversation = %+v", dnsConv)
	}
}

func TestComputeStatsEmpty(t *testing.T) {
	s := ComputeStats(nil, 10, 5)
	if s.TotalPackets != 0 || len(s.Protocols) != 0 {
		t.Errorf("empty stats not empty: %+v", s)
	}
}
