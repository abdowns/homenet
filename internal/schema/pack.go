package schema

import "labnet/internal/nql"

func PackDnsQuery(buf *nql.Buf, i int, q DnsQuery) {
	buf.SetUint(i, "ts", q.TS)
	buf.SetIP4(i, "client", q.Client[0], q.Client[1], q.Client[2], q.Client[3])
	buf.SetStr(i, "device", q.Device)
	buf.SetStr(i, "name", q.Name)
	buf.SetUint(i, "qtype", uint64(q.QType))
	buf.SetUint(i, "rcode", uint64(q.RCode))
	buf.SetBool(i, "blocked", q.Blocked)
	buf.SetBool(i, "upstream", q.Upstream)
	buf.SetF64(i, "ms", q.MS)
}

func PackHttpRequest(buf *nql.Buf, i int, r HttpRequest) {
	buf.SetUint(i, "ts", r.TS)
	buf.SetIP4(i, "client", r.Client[0], r.Client[1], r.Client[2], r.Client[3])
	buf.SetStr(i, "device", r.Device)
	buf.SetStr(i, "user", r.User)
	buf.SetStr(i, "service", r.Service)
	buf.SetStr(i, "host", r.Host)
	buf.SetStr(i, "method", r.Method)
	buf.SetStr(i, "path", r.Path)
	buf.SetStr(i, "agent", r.Agent)
	buf.SetUint(i, "status", uint64(r.Status))
	buf.SetUint(i, "bytes", uint64(r.Bytes))
	buf.SetF64(i, "ms", r.MS)
	buf.SetBool(i, "authed", r.Authed)
}

func PackAuthEvent(buf *nql.Buf, i int, e AuthEvent) {
	buf.SetUint(i, "ts", e.TS)
	buf.SetIP4(i, "client", e.Client[0], e.Client[1], e.Client[2], e.Client[3])
	buf.SetStr(i, "device", e.Device)
	buf.SetStr(i, "user", e.User)
	buf.SetStr(i, "kind", e.Kind)
	buf.SetBool(i, "ok", e.OK)
}
