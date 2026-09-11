package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"labnet/internal/ca"
	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/schema"
)

func newRing(t *testing.T) *journal.Ring {
	t.Helper()
	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compile prelude: %v", err)
	}
	t.Cleanup(func() { prog.Close() })
	ring, err := journal.NewRing(prog, "HttpRequest", 16)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	t.Cleanup(ring.Close)
	return ring
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

	ring := newRing(t)
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

	rows, _, err := ring.Query(`service == "hello" and status == 418`, 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 journaled row, got %d", len(rows))
	}
}

func TestUnregisteredHostIs404(t *testing.T) {
	p := &Proxy{Registry: NewRegistry(), Journal: newRing(t)}
	req := httptest.NewRequest(http.MethodGet, "http://nope.lab/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestPolicyDenies(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should not see this"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)

	reg := NewRegistry()
	reg.Register("admin", "admin.lab", target)

	p := &Proxy{
		Registry: reg,
		Journal:  newRing(t),
		Policy:   func(r schema.HttpRequest) bool { return r.Path == "/secret" },
	}

	req := httptest.NewRequest(http.MethodGet, "http://admin.lab/secret", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestAuthenticateGate(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret backend"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)

	reg := NewRegistry()
	reg.Register("app", "app.lab", target)

	p := &Proxy{
		Registry: reg,
		Journal:  newRing(t),
		Authenticate: func(token string) (string, bool) {
			return "phone", token == "good-token"
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.lab/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated status = %d, want 401", w.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://app.lab/", nil)
	req2.Header.Set("Authorization", "Bearer good-token")
	w2 := httptest.NewRecorder()
	p.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, body = %s", w2.Code, w2.Body)
	}

	rows, _, err := p.Journal.Query(`authed and device == "phone"`, 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 authenticated+journaled row, got %d", len(rows))
	}
}

// regression: Policy/Public must see rec.Service already populated
func TestPolicySeesServiceName(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin panel"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)

	reg := NewRegistry()
	reg.Register("admin", "admin.lab", target)

	var seenService string
	p := &Proxy{
		Registry: reg,
		Journal:  newRing(t),
		Policy: func(r schema.HttpRequest) bool {
			seenService = r.Service
			return r.Service == "admin"
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://admin.lab/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if seenService != "admin" {
		t.Errorf("Policy saw r.Service = %q, want \"admin\"", seenService)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (denied)", w.Code)
	}
}

func TestPublicBypassesAuthenticateButNotPolicy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("webhook received"))
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)

	reg := NewRegistry()
	reg.Register("ci", "ci.lab", target)

	p := &Proxy{
		Registry:     reg,
		Journal:      newRing(t),
		Authenticate: func(token string) (string, bool) { return "", false },
		Public:       func(r schema.HttpRequest) bool { return strings.HasPrefix(r.Path, "/hooks/") },
	}

	req := httptest.NewRequest(http.MethodPost, "http://ci.lab/hooks/github", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("public path status = %d, want 200, body=%s", w.Code, w.Body)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://ci.lab/dashboard", nil)
	w2 := httptest.NewRecorder()
	p.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("non-public path status = %d, want 401", w2.Code)
	}
}

func TestPairPathBypassesEverything(t *testing.T) {
	pairHit := false
	pairHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pairHit = true
		w.Write([]byte("pair form"))
	})

	p := &Proxy{
		Registry:     NewRegistry(),
		Journal:      newRing(t),
		Authenticate: func(token string) (string, bool) { return "", false },
		PairPath:     "/_labnet/pair",
		PairHandler:  pairHandler,
	}

	req := httptest.NewRequest(http.MethodGet, "http://whatever.lab/_labnet/pair", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if !pairHit {
		t.Fatal("PairHandler was not invoked")
	}
	if w.Code != http.StatusOK || w.Body.String() != "pair form" {
		t.Errorf("status=%d body=%q, want 200 \"pair form\"", w.Code, w.Body.String())
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
	p := &Proxy{Registry: reg, Journal: newRing(t)}

	srv := httptest.NewUnstartedServer(p)
	srv.TLS = &tls.Config{GetCertificate: authority.GetCertificate}
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(authority.RootCert())

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: "app.lab",
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: app.lab\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(body), "real backend response") {
		t.Fatalf("response did not contain backend body: %s", body)
	}
}
