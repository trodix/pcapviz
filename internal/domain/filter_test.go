package domain

import "testing"

func mkPkt() Packet {
	return Packet{
		Num: 1, Src: "10.0.0.1", Dst: "8.8.8.8",
		SrcPort: 51000, DstPort: 53, Proto: "DNS", Length: 74,
		Info: "Standard query A example.com",
		App:  &AppInfo{Kind: "dns", DNSName: "example.com"},
	}
}

func TestFilter(t *testing.T) {
	p := mkPkt()
	cases := []struct {
		expr string
		want bool
	}{
		{"dns", true},
		{"tcp", false},
		{"udp.port == 53", true},
		{"port == 53", true},
		{"port == 80", false},
		{"ip.addr == 8.8.8.8", true},
		{"ip.src == 8.8.8.8", false},
		{"ip.dst == 8.8.8.8", true},
		{"proto == dns", true},
		{"proto != tcp", true},
		{"length > 50", true},
		{"length > 100", false},
		{"length >= 74 && length <= 74", true},
		{"dns.name == example.com", true},
		{"dns.name == other.com", false},
		{"!tcp", true},
		{"!dns", false},
		{"dns && ip.addr == 10.0.0.1", true},
		{"tcp || dns", true},
		{"(tcp || udp) && port == 53", false}, // proto is DNS, not tcp/udp
		{"info == \"Standard query A example.com\"", true},
	}
	for _, c := range cases {
		f, err := ParseFilter(c.expr)
		if err != nil {
			t.Fatalf("ParseFilter(%q) error: %v", c.expr, err)
		}
		if got := f.Eval(p); got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestFilterErrors(t *testing.T) {
	for _, expr := range []string{"", "ip.addr ==", "bogus.field == 1", "tcp.port", "( tcp", "\"unterminated"} {
		if _, err := ParseFilter(expr); err == nil {
			t.Errorf("ParseFilter(%q) expected error, got nil", expr)
		}
	}
}
