package proxy

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/schema"
)

type Proxy struct {
	Registry *Registry
	Journal  *journal.Ring
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
	t0 := time.Now()
	host := StripPort(r.Host)
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

	svc, ok := p.Registry.Lookup(host)
	if ok {
		svc.rp.ServeHTTP(sw, r)
	} else {
		http.Error(sw, fmt.Sprintf("labnet: no service registered for %q", host), http.StatusNotFound)
	}

	rec := schema.HttpRequest{
		TS:     uint64(t0.UnixMilli()),
		Client: clientAddr(r.RemoteAddr),
		Host:   host,
		Method: r.Method,
		Path:   r.URL.Path,
		Agent:  r.UserAgent(),
		Status: uint16(sw.status),
		Bytes:  uint32(sw.bytes),
		MS:     float64(time.Since(t0)) / float64(time.Millisecond),
	}
	if ok {
		rec.Service = svc.Name
	}
	p.Journal.Append(func(buf *nql.Buf, i int) { schema.PackHttpRequest(buf, i, rec) })
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
