// filter name prefix decides behavior: deny_/allow_/public_/alert_ on
// httprequest, block_/alert_ on dnsquery, alert_ on authevent
package policy

import (
	"strings"
	"unsafe"

	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/schema"
)

type rule struct {
	name string
	k    nql.Kernels
}

type Policy struct {
	prog *nql.Program

	denyHTTP, allowHTTP, publicHTTP, alertHTTP []rule
	blockDNS, alertDNS                         []rule
	alertAuth                                  []rule
}

// empty src compiles fine and denies nothing
func Compile(src string) (*Policy, error) {
	prog, err := nql.Compile(schema.Prelude, src)
	if err != nil {
		return nil, err
	}
	p := &Policy{prog: prog}
	for _, fi := range prog.Filters() {
		k, ok := prog.FilterKernels(fi.Name)
		if !ok {
			continue // unreachable: fi came from this same prog
		}
		r := rule{name: fi.Name, k: k}
		switch {
		case fi.SchemaName == "HttpRequest" && strings.HasPrefix(fi.Name, "deny_"):
			p.denyHTTP = append(p.denyHTTP, r)
		case fi.SchemaName == "HttpRequest" && strings.HasPrefix(fi.Name, "allow_"):
			p.allowHTTP = append(p.allowHTTP, r)
		case fi.SchemaName == "HttpRequest" && strings.HasPrefix(fi.Name, "public_"):
			p.publicHTTP = append(p.publicHTTP, r)
		case fi.SchemaName == "HttpRequest" && strings.HasPrefix(fi.Name, "alert_"):
			p.alertHTTP = append(p.alertHTTP, r)
		case fi.SchemaName == "DnsQuery" && strings.HasPrefix(fi.Name, "block_"):
			p.blockDNS = append(p.blockDNS, r)
		case fi.SchemaName == "DnsQuery" && strings.HasPrefix(fi.Name, "alert_"):
			p.alertDNS = append(p.alertDNS, r)
		case fi.SchemaName == "AuthEvent" && strings.HasPrefix(fi.Name, "alert_"):
			p.alertAuth = append(p.alertAuth, r)
			// no case match (unrecognized prefix, or prefix over the wrong
			// schema) is deliberate: it compiles but has no policy effect
		}
	}
	return p, nil
}

func (p *Policy) Close() { p.prog.Close() }

func (p *Policy) RuleNames() map[string][]string {
	names := func(rs []rule) []string {
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = r.name
		}
		return out
	}
	return map[string][]string{
		"deny_":   names(p.denyHTTP),
		"allow_":  names(p.allowHTTP),
		"public_": names(p.publicHTTP),
		"block_":  names(p.blockDNS),
		"alert_":  append(append(names(p.alertHTTP), names(p.alertDNS)...), names(p.alertAuth)...),
	}
}

func evalFirst(prog *nql.Program, schemaName string, rules []rule, fill func(buf *nql.Buf, i int)) (matched bool, name string) {
	if len(rules) == 0 {
		return false, ""
	}
	sch, ok := prog.Schema(schemaName)
	if !ok {
		return false, "" // schema.Prelude always declares it; defensive only
	}
	buf := nql.NewBuf(sch, 1)
	defer buf.Free()
	fill(buf, 0)
	rec := buf.Rec(0)
	for _, r := range rules {
		if r.k.Pred(rec) {
			return true, r.name
		}
	}
	return false, ""
}

func evalAll(prog *nql.Program, schemaName string, rules []rule, fill func(buf *nql.Buf, i int)) []string {
	if len(rules) == 0 {
		return nil
	}
	sch, ok := prog.Schema(schemaName)
	if !ok {
		return nil
	}
	buf := nql.NewBuf(sch, 1)
	defer buf.Free()
	fill(buf, 0)
	rec := buf.Rec(0)
	var names []string
	for _, r := range rules {
		if r.k.Pred(rec) {
			names = append(names, r.name)
		}
	}
	return names
}

func fillHTTP(r schema.HttpRequest) func(buf *nql.Buf, i int) {
	return func(buf *nql.Buf, i int) { schema.PackHttpRequest(buf, i, r) }
}
func fillDNS(q schema.DnsQuery) func(buf *nql.Buf, i int) {
	return func(buf *nql.Buf, i int) { schema.PackDnsQuery(buf, i, q) }
}
func fillAuth(e schema.AuthEvent) func(buf *nql.Buf, i int) {
	return func(buf *nql.Buf, i int) { schema.PackAuthEvent(buf, i, e) }
}

func (p *Policy) IsPublicHTTP(r schema.HttpRequest) (bool, string) {
	return evalFirst(p.prog, "HttpRequest", p.publicHTTP, fillHTTP(r))
}

// allow_ wins over deny_
func (p *Policy) DenyHTTP(r schema.HttpRequest) (bool, string) {
	denied, name := evalFirst(p.prog, "HttpRequest", p.denyHTTP, fillHTTP(r))
	if !denied {
		return false, ""
	}
	if allowed, _ := evalFirst(p.prog, "HttpRequest", p.allowHTTP, fillHTTP(r)); allowed {
		return false, ""
	}
	return true, name
}

func (p *Policy) AlertsHTTP(r schema.HttpRequest) []string {
	return evalAll(p.prog, "HttpRequest", p.alertHTTP, fillHTTP(r))
}

func (p *Policy) BlockDNS(q schema.DnsQuery) (bool, string) {
	return evalFirst(p.prog, "DnsQuery", p.blockDNS, fillDNS(q))
}

func (p *Policy) AlertsDNS(q schema.DnsQuery) []string {
	return evalAll(p.prog, "DnsQuery", p.alertDNS, fillDNS(q))
}

func (p *Policy) AlertsAuth(e schema.AuthEvent) []string {
	return evalAll(p.prog, "AuthEvent", p.alertAuth, fillAuth(e))
}

type TestResult struct {
	HTTPTotal, HTTPDenied int
	DNSTotal, DNSBlocked  int
	DeniedBy, BlockedBy   map[string]int
}

func (p *Policy) TestHTTP(rows []schema.HttpRequest) TestResult {
	res := TestResult{HTTPTotal: len(rows), DeniedBy: map[string]int{}, BlockedBy: map[string]int{}}
	for _, r := range rows {
		if denied, name := p.DenyHTTP(r); denied {
			res.HTTPDenied++
			res.DeniedBy[name]++
		}
	}
	return res
}

func (p *Policy) TestDNS(rows []schema.DnsQuery) TestResult {
	res := TestResult{DNSTotal: len(rows), DeniedBy: map[string]int{}, BlockedBy: map[string]int{}}
	for _, q := range rows {
		if blocked, name := p.BlockDNS(q); blocked {
			res.DNSBlocked++
			res.BlockedBy[name]++
		}
	}
	return res
}

// safe because the ring's program and this policy's program were compiled
// from the identical schema.Prelude text, so record layouts match byte for
// byte despite being two separate nql.Program instances
func (p *Policy) TestHTTPRing(ring *journal.Ring) TestResult {
	res := TestResult{DeniedBy: map[string]int{}, BlockedBy: map[string]int{}}
	ring.Scan(func(rec unsafe.Pointer) {
		res.HTTPTotal++
		denied, name := false, ""
		for _, r := range p.denyHTTP {
			if r.k.Pred(rec) {
				denied, name = true, r.name
				break
			}
		}
		if denied {
			for _, r := range p.allowHTTP {
				if r.k.Pred(rec) {
					denied = false
					break
				}
			}
		}
		if denied {
			res.HTTPDenied++
			res.DeniedBy[name]++
		}
	})
	return res
}

func (p *Policy) TestDNSRing(ring *journal.Ring) TestResult {
	res := TestResult{DeniedBy: map[string]int{}, BlockedBy: map[string]int{}}
	ring.Scan(func(rec unsafe.Pointer) {
		res.DNSTotal++
		for _, r := range p.blockDNS {
			if r.k.Pred(rec) {
				res.DNSBlocked++
				res.BlockedBy[r.name]++
				return
			}
		}
	})
	return res
}
