package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"labnet/internal/ca"
	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/schema"
)

func newJournal(t *testing.T) (*journal.Ring, func()) {
	t.Helper()
	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compile prelude: %v", err)
	}
	ring, err := journal.NewRing(prog, "HttpRequest", 16)
	if err != nil {
		prog.Close()
		t.Fatalf("NewRing: %v", err)
	}
	return ring, func() {
		ring.Close()
		prog.Close()
	}
}

func TestRoutingAndJournaling(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)

	reg := NewRegistry()
	reg.Register("hello", "hello.lab", target)

	ring, done := newJournal(t)
	defer done()
	p := &Proxy{Registry: reg, Journal: ring}

	req := httptest.NewRequest(http.MethodGet, "http://hello.lab/foo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if string(body) != "hello from backend" {
		t.Errorf("body = %q", body)
	}

	rows, _, err := ring.Query(`service == "hello"`, 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 journaled row, got %d", len(rows))
	}
}

func TestUnregisteredHostIs404(t *testing.T) {
	ring, done := newJournal(t)
	defer done()
	p := &Proxy{Registry: NewRegistry(), Journal: ring}
	req := httptest.NewRequest(http.MethodGet, "http://nope.lab/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestEndToEndTLS(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("real backend response"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)

	reg := NewRegistry()
	reg.Register("app", "app.lab", target)

	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	ring, done := newJournal(t)
	defer done()
	p := &Proxy{Registry: reg, Journal: ring}

	srv := httptest.NewUnstartedServer(p)
	srv.TLS = &tls.Config{GetCertificate: authority.GetCertificate}
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(authority.RootCert())

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "app.lab"},
	}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Host = "app.lab"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "real backend response" {
		t.Fatalf("body = %q", body)
	}
}
