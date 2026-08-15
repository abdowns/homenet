package ca

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersists(t *testing.T) {
	dir := t.TempDir()

	c1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate (create): %v", err)
	}
	if !c1.cert.IsCA {
		t.Error("root certificate is not marked as a CA")
	}

	c2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate (load): %v", err)
	}
	if c2.cert.SerialNumber.Cmp(c1.cert.SerialNumber) != 0 {
		t.Error("second LoadOrCreate generated a new root instead of loading the persisted one")
	}
}

func TestGetCertificateCaching(t *testing.T) {
	c, err := LoadOrCreate(filepath.Join(t.TempDir()))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	hello := &tls.ClientHelloInfo{ServerName: "app.lab"}

	leaf1, err := c.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	leaf2, err := c.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate (again): %v", err)
	}
	if leaf1 != leaf2 {
		t.Error("GetCertificate minted a new leaf on the second call instead of returning the cached one")
	}

	other, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.lab"})
	if err != nil {
		t.Fatalf("GetCertificate(other.lab): %v", err)
	}
	if other == leaf1 {
		t.Error("different hostnames got the same cached leaf")
	}

	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
		t.Error("expected an error for an empty SNI server name")
	}
}

func TestRealHandshakeTrustsRoot(t *testing.T) {
	c, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{GetCertificate: c.GetCertificate}
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(c.RootCert())

	// serverName is app.lab, not the listener addr, matching what a real client checks
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: "app.lab",
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != "app.lab" {
		t.Fatalf("unexpected peer certificate: %+v", cs.PeerCertificates)
	}
}
