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
		t.Error("a missing policy file should behave as an empty policy")
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

	newSrc := `filter deny_admin(r: HttpRequest) { r.path startswith "/admin" }`
	if err := os.WriteFile(path, []byte(newSrc), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if denied, _ := m.Current().DenyHTTP(schema.HttpRequest{Path: "/admin/x"}); !denied {
		t.Error("after reload the new policy should deny /admin/x")
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
	defer close(stop)
	go m.Watch(stop)

	// let the watcher start before triggering the change
	time.Sleep(100 * time.Millisecond)

	newSrc := `filter deny_admin(r: HttpRequest) { r.path startswith "/admin" }`
	if err := os.WriteFile(path, []byte(newSrc), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	if denied, _ := m.Current().DenyHTTP(schema.HttpRequest{Path: "/admin/x"}); !denied {
		t.Fatal("Watch did not pick up the policy file change")
	}
}
