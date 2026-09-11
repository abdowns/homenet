package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"

	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/schema"
)

type PolicyFunc func(r schema.HttpRequest) (deny bool)

type AuthenticateFunc func(r *http.Request) (deviceID, deviceName string, ok bool)

type Proxy struct {
	Registry *Registry
	Journal  *journal.Ring
	Policy   PolicyFunc // nil: never deny

	// gates every request except PairPath or a Public exemption
	Authenticate AuthenticateFunc
	// exempts from Authenticate but not Policy
	Public PolicyFunc
	// served directly, bypassing registry/authenticate/policy, any host
	PairPath    string
	PairHandler http.Handler
}

func clientAddr(remote string) [4]byte {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	v4 := net.ParseIP(host).To4()
	if v4 == nil {
		return [4]byte{}
	}
	return [4]byte{v4[0], v4[1], v4[2], v4[3]}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.PairHandler != nil && p.PairPath != "" && r.URL.Path == p.PairPath {
		p.PairHandler.ServeHTTP(w, r) // any hostname pairs a device; not journaled
		return
	}

	t0 := time.Now()
	host := StripPort(r.Host)

	rec := schema.HttpRequest{
		TS:     uint64(t0.UnixMilli()),
		Client: clientAddr(r.RemoteAddr),
		Host:   host,
		Method: r.Method,
		Path:   r.URL.Path,
		Agent:  r.UserAgent(),
	}
	var authed bool
	if p.Authenticate != nil {
		_, rec.Device, authed = p.Authenticate(r)
	}
	rec.Authed = authed

	// rec.service must be set before Public/Policy run, since a rule can
	// key on it (e.g. r.service == "admin") and would never match a blank one
	svc, foundSvc := p.Registry.Lookup(host)
	if foundSvc {
		rec.Service = svc.Name
	}
	isPublic := p.Public != nil && p.Public(rec)

	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

	switch {
	case p.Authenticate != nil && !authed && !isPublic:
		http.Error(sw, fmt.Sprintf("labnet: this device isn't paired — open %s on any *.lab address to pair it", orDefault(p.PairPath, "/_labnet/pair")), http.StatusUnauthorized)
	case p.Policy != nil && p.Policy(rec):
		http.Error(sw, "labnet: denied by policy", http.StatusForbidden)
	case !foundSvc:
		http.Error(sw, fmt.Sprintf("labnet: no service registered for %q (try `labnet up` or `labnet expose`)", host), http.StatusNotFound)
	default:
		svc.rp.ServeHTTP(sw, r)
	}

	rec.Status = uint16(sw.status)
	rec.Bytes = uint32(sw.bytes)
	rec.MS = float64(time.Since(t0)) / float64(time.Millisecond)
	p.Journal.Append(func(buf *nql.Buf, i int) { schema.PackHttpRequest(buf, i, rec) })
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// passes through Flush/Hijack so streaming and websocket/hmr upgrades keep working
type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("labnet: underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}
