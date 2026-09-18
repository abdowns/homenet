package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"labnet/internal/schema"
)

func TestNewManagerMissingFileIsNoOp(t *testing.T) {
	m, err := NewManager(filepath.Join(t.TempDir(), "does-not-exist.nql"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if denied, _ := m.Current().DenyHTTP(schema.HttpRequest{Path: "/admin"}); denied {
		t.Error("a missing policy file should behave as an empty (no-op) policy")
	}
}

func TestNewManagerInvalidFileIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.nql")
	if err := os.WriteFile(path, []byte("not valid nql {{{"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewManager(path); err == nil {
		t.Fatal("expected an error for an invalid initial policy file")
	}
}

func TestReloadSwapsInNewPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.nql")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	m, err := NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if denied, _ := m.Current().DenyHTTP(schema.HttpRequest{Path: "/admin"}); denied {
		t.Fatal("initial empty policy should not deny")
	}

	newSrc := `filter deny_admin(r: HttpRequest) { r.path startswith "/admin" }`
	if err := os.WriteFile(path, []byte(newSrc), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if denied, rule := m.Current().DenyHTTP(schema.HttpRequest{Path: "/admin/x"}); !denied || rule != "deny_admin" {
		t.Errorf("after reload: denied=%v rule=%q, want true/deny_admin", denied, rule)
	}
}

func TestSourceTracksActivePolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.nql")
	initial := `filter deny_admin(r: HttpRequest) { r.path startswith "/admin" }`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	m, err := NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m.Source() != initial {
		t.Errorf("Source() = %q, want %q", m.Source(), initial)
	}

	updated := `filter block_ads(q: DnsQuery) { q.name matches "*ads*" }`
	if err := m.Apply(updated); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if m.Source() != updated {
		t.Errorf("Source() after Apply = %q, want %q", m.Source(), updated)
	}

	if err := os.WriteFile(path, []byte("broken {{{"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("expected Reload to fail")
	}
	if m.Source() != updated {
		t.Errorf("Source() after failed reload = %q, want unchanged %q", m.Source(), updated)
	}
}

func TestReloadKeepsOldPolicyOnCompileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.nql")
	goodSrc := `filter deny_admin(r: HttpRequest) { r.path startswith "/admin" }`
	if err := os.WriteFile(path, []byte(goodSrc), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	m, err := NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if err := os.WriteFile(path, []byte("broken {{{ nql"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("expected Reload to fail on invalid NQL")
	}

	if denied, rule := m.Current().DenyHTTP(schema.HttpRequest{Path: "/admin/x"}); !denied || rule != "deny_admin" {
		t.Errorf("after failed reload: denied=%v rule=%q, want true/deny_admin (old policy preserved)", denied, rule)
	}
}

func TestReloadOnMissingFileRevertsToNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.nql")
	goodSrc := `filter deny_admin(r: HttpRequest) { r.path startswith "/admin" }`
	if err := os.WriteFile(path, []byte(goodSrc), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	m, err := NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload after removing the file: %v", err)
	}
	if denied, _ := m.Current().DenyHTTP(schema.HttpRequest{Path: "/admin/x"}); denied {
		t.Error("after the policy file is removed, policy should revert to no-op")
	}
}

func TestWatchPicksUpChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.nql")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	m, err := NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- m.Watch(stop) }()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	// let the watcher start before triggering the change
	time.Sleep(100 * time.Millisecond)

	newSrc := `filter deny_admin(r: HttpRequest) { r.path startswith "/admin" }`
	if err := os.WriteFile(path, []byte(newSrc), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if denied, _ := m.Current().DenyHTTP(schema.HttpRequest{Path: "/admin/x"}); denied {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Watch did not pick up the policy file change within the deadline")
}
