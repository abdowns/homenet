package proxy

import (
	"net/url"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", s, err)
	}
	return u
}

func TestRegistryLookupNormalizesHost(t *testing.T) {
	r := NewRegistry()
	r.Register("app", "App.Lab.", mustURL(t, "http://127.0.0.1:1234"))

	for _, h := range []string{"app.lab", "App.Lab", "app.lab.", "APP.LAB."} {
		if _, ok := r.Lookup(h); !ok {
			t.Errorf("Lookup(%q): not found", h)
		}
	}
	if _, ok := r.Lookup("other.lab"); ok {
		t.Error("Lookup(other.lab): unexpectedly found")
	}
}

func TestRegistryDeregister(t *testing.T) {
	r := NewRegistry()
	r.Register("app", "app.lab", mustURL(t, "http://127.0.0.1:1234"))

	if !r.Deregister("app.lab") {
		t.Fatal("Deregister: expected true")
	}
	if r.Deregister("app.lab") {
		t.Fatal("Deregister (again): expected false")
	}
	if _, ok := r.Lookup("app.lab"); ok {
		t.Error("app.lab still found after Deregister")
	}
}

func TestRegistryDeregisterByName(t *testing.T) {
	r := NewRegistry()
	r.Register("app", "app.lab", mustURL(t, "http://127.0.0.1:1"))
	r.Register("other", "other.lab", mustURL(t, "http://127.0.0.1:2"))

	if !r.DeregisterByName("app") {
		t.Fatal("DeregisterByName(app): expected true")
	}
	if _, ok := r.Lookup("app.lab"); ok {
		t.Error("app.lab still found")
	}
	if _, ok := r.Lookup("other.lab"); !ok {
		t.Error("other.lab was unexpectedly removed too")
	}
	if r.DeregisterByName("nosuch") {
		t.Error("DeregisterByName(nosuch): expected false")
	}
}

func TestRegistryRegisterReplaces(t *testing.T) {
	r := NewRegistry()
	r.Register("app", "app.lab", mustURL(t, "http://127.0.0.1:1"))
	r.Register("app", "app.lab", mustURL(t, "http://127.0.0.1:2"))

	if len(r.List()) != 1 {
		t.Fatalf("expected 1 entry after re-registering the same host, got %d", len(r.List()))
	}
	svc, _ := r.Lookup("app.lab")
	if svc.Target.Port() != "2" {
		t.Errorf("Target = %s, want port 2 (the latest registration)", svc.Target)
	}
}

func TestStripPort(t *testing.T) {
	cases := map[string]string{
		"app.lab:8443": "app.lab",
		"app.lab":      "app.lab",
		"app.lab.":     "app.lab.",
	}
	for in, want := range cases {
		if got := StripPort(in); got != want {
			t.Errorf("StripPort(%q) = %q, want %q", in, got, want)
		}
	}
}
