// filter name prefix decides behavior: deny_ on httprequest, block_ on
// dnsquery
package policy

import (
	"strings"

	"labnet/internal/nql"
	"labnet/internal/schema"
)

type Policy struct {
	prog *nql.Program

	deny  map[string]nql.Kernels
	block map[string]nql.Kernels
}

func Compile(src string) (*Policy, error) {
	p := &Policy{deny: map[string]nql.Kernels{}, block: map[string]nql.Kernels{}}
	if strings.TrimSpace(src) == "" {
		return p, nil
	}
	prog, err := nql.Compile(schema.Prelude, src)
	if err != nil {
		return nil, err
	}
	p.prog = prog
	for _, fi := range prog.Filters() {
		k, ok := prog.FilterKernels(fi.Name)
		if !ok {
			continue
		}
		switch {
		case fi.SchemaName == "HttpRequest" && strings.HasPrefix(fi.Name, "deny_"):
			p.deny[fi.Name] = k
		case fi.SchemaName == "DnsQuery" && strings.HasPrefix(fi.Name, "block_"):
			p.block[fi.Name] = k
		}
	}
	return p, nil
}

func (p *Policy) DenyHTTP(r schema.HttpRequest) (bool, string) {
	if len(p.deny) == 0 {
		return false, ""
	}
	sch, _ := p.prog.Schema("HttpRequest")
	buf := nql.NewBuf(sch, 1)
	defer buf.Free()
	schema.PackHttpRequest(buf, 0, r)
	rec := buf.Rec(0)
	for name, k := range p.deny {
		if k.Pred(rec) {
			return true, name
		}
	}
	return false, ""
}

func (p *Policy) BlockDNS(q schema.DnsQuery) (bool, string) {
	if len(p.block) == 0 {
		return false, ""
	}
	sch, _ := p.prog.Schema("DnsQuery")
	buf := nql.NewBuf(sch, 1)
	defer buf.Free()
	schema.PackDnsQuery(buf, 0, q)
	rec := buf.Rec(0)
	for name, k := range p.block {
		if k.Pred(rec) {
			return true, name
		}
	}
	return false, ""
}
