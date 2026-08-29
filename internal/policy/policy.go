// filter name prefix decides behavior: deny_ on httprequest, block_ on
// dnsquery
package policy

import (
	"fmt"
	"strings"

	"labnet/internal/nql"
	"labnet/internal/schema"
)

type rule struct {
	name string
	k    nql.Kernels
}

type Policy struct {
	prog *nql.Program

	denyHTTP []rule
	blockDNS []rule
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
		case fi.SchemaName == "DnsQuery" && strings.HasPrefix(fi.Name, "block_"):
			p.blockDNS = append(p.blockDNS, r)
		}
	}
	return p, nil
}

func (p *Policy) Close() { p.prog.Close() }

func (p *Policy) Summary() string {
	return fmt.Sprintf("%d deny_, %d block_", len(p.denyHTTP), len(p.blockDNS))
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

func (p *Policy) DenyHTTP(r schema.HttpRequest) (bool, string) {
	return evalFirst(p.prog, "HttpRequest", p.denyHTTP, func(buf *nql.Buf, i int) {
		schema.PackHttpRequest(buf, i, r)
	})
}

func (p *Policy) BlockDNS(q schema.DnsQuery) (bool, string) {
	return evalFirst(p.prog, "DnsQuery", p.blockDNS, func(buf *nql.Buf, i int) {
		schema.PackDnsQuery(buf, i, q)
	})
}
