package schema

import "labnet/internal/nql"

func PackDnsQuery(buf *nql.Buf, i int, q DnsQuery) {
	c := q.Client
	buf.SetUint(i, "ts", q.TS)
	buf.SetIP4(i, "client", c[0], c[1], c[2], c[3])
	buf.SetStr(i, "name", q.Name)
	buf.SetUint(i, "qtype", uint64(q.QType))
	buf.SetUint(i, "rcode", uint64(q.RCode))
	buf.SetBool(i, "blocked", q.Blocked)
	buf.SetBool(i, "upstream", q.Upstream)
	buf.SetF64(i, "ms", q.MS)
}

func PackHttpRequest(buf *nql.Buf, i int, r HttpRequest) {
	c := r.Client
	buf.SetUint(i, "ts", r.TS)
	buf.SetIP4(i, "client", c[0], c[1], c[2], c[3])
	buf.SetStr(i, "service", r.Service)
	buf.SetStr(i, "host", r.Host)
	buf.SetStr(i, "method", r.Method)
	buf.SetStr(i, "path", r.Path)
	buf.SetStr(i, "agent", r.Agent)
	buf.SetUint(i, "status", uint64(r.Status))
	buf.SetUint(i, "bytes", uint64(r.Bytes))
	buf.SetF64(i, "ms", r.MS)
}
