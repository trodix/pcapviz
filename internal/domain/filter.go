package domain

import (
	"fmt"
	"strconv"
	"strings"
)

// Filter is a compiled display-filter predicate over packets. Build one with
// ParseFilter, then call Eval for each packet.
//
// Supported grammar (a pragmatic subset of Wireshark's display filters):
//
//	expr        := or
//	or          := and ( "||" and )*
//	and         := unary ( "&&" unary )*
//	unary       := "!" unary | primary
//	primary     := "(" expr ")" | comparison | protoKeyword
//	comparison  := field op value
//	op          := "==" | "!=" | ">" | ">=" | "<" | "<="
//	field       := ip.addr | ip.src | ip.dst | port | tcp.port | udp.port |
//	               proto | length | dns.name | http.host | tls.sni | info
//	protoKeyword:= tcp | udp | dns | http | tls | icmp | arp  (shorthand: proto == X)
//
// Examples:
//
//	tcp.port == 443 && ip.addr == 10.0.0.1
//	dns || http
//	!arp && length > 100
type Filter struct {
	root node
}

// Eval reports whether the packet matches the filter.
func (f Filter) Eval(p Packet) bool { return f.root.eval(p) }

// MatchAll is the predicate that accepts every packet (empty filter).
func MatchAll(Packet) bool { return true }

// ParseFilter compiles a display-filter expression. An empty/whitespace string
// is rejected; callers should treat the empty filter as MatchAll themselves.
func ParseFilter(expr string) (Filter, error) {
	toks, err := lex(expr)
	if err != nil {
		return Filter{}, err
	}
	p := &parser{toks: toks}
	n, err := p.parseExpr()
	if err != nil {
		return Filter{}, err
	}
	if p.pos != len(p.toks) {
		return Filter{}, fmt.Errorf("unexpected token %q", p.toks[p.pos].val)
	}
	return Filter{root: n}, nil
}

// --- AST ---

type node interface{ eval(p Packet) bool }

type andNode struct{ l, r node }

func (n andNode) eval(p Packet) bool { return n.l.eval(p) && n.r.eval(p) }

type orNode struct{ l, r node }

func (n orNode) eval(p Packet) bool { return n.l.eval(p) || n.r.eval(p) }

type notNode struct{ x node }

func (n notNode) eval(p Packet) bool { return !n.x.eval(p) }

type protoNode struct{ name string }

func (n protoNode) eval(p Packet) bool {
	if strings.EqualFold(p.Proto, n.name) {
		return true
	}
	// dns/http/tls also match when only carried as app info over TCP/UDP.
	return p.App != nil && strings.EqualFold(p.App.Kind, n.name)
}

type cmpNode struct {
	field string
	op    string
	val   string
}

func (n cmpNode) eval(p Packet) bool {
	switch n.field {
	case "ip.addr", "port", "tcp.port", "udp.port":
		// match against either side
		a, b := n.sides(p)
		return n.cmpStr(a) || n.cmpStr(b)
	case "ip.src":
		return n.cmpStr(p.Src)
	case "ip.dst":
		return n.cmpStr(p.Dst)
	case "proto":
		return n.cmpStr(p.Proto)
	case "length":
		return n.cmpInt(p.Length)
	case "info":
		return n.cmpContains(p.Info)
	case "dns.name":
		return p.App != nil && n.cmpContains(p.App.DNSName)
	case "http.host":
		return p.App != nil && n.cmpContains(p.App.HTTPHost)
	case "tls.sni":
		return p.App != nil && n.cmpContains(p.App.TLSSNI)
	}
	return false
}

func (n cmpNode) sides(p Packet) (string, string) {
	switch n.field {
	case "ip.addr":
		return p.Src, p.Dst
	default: // port variants
		return strconv.Itoa(p.SrcPort), strconv.Itoa(p.DstPort)
	}
}

func (n cmpNode) cmpStr(actual string) bool {
	switch n.op {
	case "==":
		return strings.EqualFold(actual, n.val)
	case "!=":
		return !strings.EqualFold(actual, n.val)
	}
	return n.cmpInt0(actual)
}

func (n cmpNode) cmpInt(actual int) bool { return n.cmpIntVal(actual) }

func (n cmpNode) cmpInt0(actual string) bool {
	av, err := strconv.Atoi(actual)
	if err != nil {
		return false
	}
	return n.cmpIntVal(av)
}

func (n cmpNode) cmpIntVal(av int) bool {
	bv, err := strconv.Atoi(n.val)
	if err != nil {
		return false
	}
	switch n.op {
	case "==":
		return av == bv
	case "!=":
		return av != bv
	case ">":
		return av > bv
	case ">=":
		return av >= bv
	case "<":
		return av < bv
	case "<=":
		return av <= bv
	}
	return false
}

func (n cmpNode) cmpContains(actual string) bool {
	switch n.op {
	case "==":
		return strings.EqualFold(actual, n.val)
	case "!=":
		return !strings.EqualFold(actual, n.val)
	}
	return false
}

// --- lexer ---

type tokenKind int

const (
	tIdent tokenKind = iota
	tOp
	tAnd
	tOr
	tNot
	tLParen
	tRParen
)

type token struct {
	kind tokenKind
	val  string
}

func lex(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(':
			toks = append(toks, token{tLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tRParen, ")"})
			i++
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			toks = append(toks, token{tAnd, "&&"})
			i += 2
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			toks = append(toks, token{tOr, "||"})
			i += 2
		case c == '=' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{tOp, "=="})
			i += 2
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{tOp, "!="})
			i += 2
		case c == '!':
			toks = append(toks, token{tNot, "!"})
			i++
		case c == '>' || c == '<':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, token{tOp, string(c) + "="})
				i += 2
			} else {
				toks = append(toks, token{tOp, string(c)})
				i++
			}
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated string")
			}
			toks = append(toks, token{tIdent, s[i+1 : j]})
			i = j + 1
		default:
			// bareword: identifiers, field names, ip addresses, numbers
			j := i
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("unexpected character %q", string(c))
			}
			toks = append(toks, token{tIdent, s[i:j]})
			i = j
		}
	}
	return toks, nil
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '.' || b == ':' || b == '_' || b == '-' || b == '/' || b == '%'
}

// --- parser ---

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() (token, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return token{}, false
}

func (p *parser) parseExpr() (node, error) { return p.parseOr() }

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tOr {
			return left, nil
		}
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tAnd {
			return left, nil
		}
		p.pos++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
}

func (p *parser) parseUnary() (node, error) {
	if t, ok := p.peek(); ok && t.kind == tNot {
		p.pos++
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{x}, nil
	}
	return p.parsePrimary()
}

var knownFields = map[string]bool{
	"ip.addr": true, "ip.src": true, "ip.dst": true, "port": true,
	"tcp.port": true, "udp.port": true, "proto": true, "length": true,
	"info": true, "dns.name": true, "http.host": true, "tls.sni": true,
}

var protoKeywords = map[string]bool{
	"tcp": true, "udp": true, "dns": true, "http": true,
	"tls": true, "icmp": true, "arp": true, "ipv6": true,
}

func (p *parser) parsePrimary() (node, error) {
	t, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("unexpected end of filter")
	}
	if t.kind == tLParen {
		p.pos++
		n, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		c, ok := p.peek()
		if !ok || c.kind != tRParen {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		p.pos++
		return n, nil
	}
	if t.kind != tIdent {
		return nil, fmt.Errorf("unexpected token %q", t.val)
	}
	field := strings.ToLower(t.val)
	// proto shorthand keyword (not followed by an operator)
	if protoKeywords[field] {
		if nx, ok := p.peekAt(1); !ok || nx.kind != tOp {
			p.pos++
			return protoNode{field}, nil
		}
	}
	if !knownFields[field] {
		return nil, fmt.Errorf("unknown field %q", t.val)
	}
	p.pos++
	op, ok := p.peek()
	if !ok || op.kind != tOp {
		return nil, fmt.Errorf("expected operator after %q", field)
	}
	p.pos++
	val, ok := p.peek()
	if !ok || val.kind != tIdent {
		return nil, fmt.Errorf("expected value after operator")
	}
	p.pos++
	return cmpNode{field: field, op: op.val, val: val.val}, nil
}

func (p *parser) peekAt(n int) (token, bool) {
	if p.pos+n < len(p.toks) {
		return p.toks[p.pos+n], true
	}
	return token{}, false
}
