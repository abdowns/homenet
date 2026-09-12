package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBootstrapCodeLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	code1, err := s.EnsureBootstrapCode(ctx, time.Hour)
	if err != nil {
		t.Fatalf("EnsureBootstrapCode: %v", err)
	}
	if len(code1) != 6 {
		t.Fatalf("expected a 6-digit code, got %q", code1)
	}

	code2, err := s.EnsureBootstrapCode(ctx, time.Hour)
	if err != nil {
		t.Fatalf("EnsureBootstrapCode (again): %v", err)
	}
	if code2 != code1 {
		t.Errorf("expected the same bootstrap code, got %q then %q", code1, code2)
	}

	if _, _, err := s.RedeemPairingCode(ctx, code1, "first-device"); err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}

	code3, err := s.EnsureBootstrapCode(ctx, time.Hour)
	if err != nil {
		t.Fatalf("EnsureBootstrapCode (post-pair): %v", err)
	}
	if code3 != "" {
		t.Errorf("expected no bootstrap code after a device paired, got %q", code3)
	}
}

func TestRedeemPairingCode(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	code, err := s.CreatePairingCode(ctx, time.Hour)
	if err != nil {
		t.Fatalf("CreatePairingCode: %v", err)
	}

	id, token, err := s.RedeemPairingCode(ctx, code, "phone")
	if err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}
	if id == "" || token == "" {
		t.Fatalf("expected non-empty id and token, got id=%q token=%q", id, token)
	}

	if _, _, err := s.RedeemPairingCode(ctx, code, "another-device"); err != ErrInvalidCode {
		t.Errorf("re-redeeming a used code: err = %v, want ErrInvalidCode", err)
	}

	if _, _, err := s.RedeemPairingCode(ctx, "000000", "x"); err != ErrInvalidCode {
		t.Errorf("unknown code: err = %v, want ErrInvalidCode", err)
	}

	gotID, gotName, ok, err := s.AuthenticateToken(ctx, token)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if !ok || gotID != id || gotName != "phone" {
		t.Errorf("AuthenticateToken = (%q, %q, %v), want (%q, phone, true)", gotID, gotName, ok, id)
	}

	if _, _, ok, err := s.AuthenticateToken(ctx, "not-a-real-token"); err != nil || ok {
		t.Errorf("AuthenticateToken(garbage) = ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestRedeemExpiredCode(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	code, err := s.CreatePairingCode(ctx, -time.Second) // already expired
	if err != nil {
		t.Fatalf("CreatePairingCode: %v", err)
	}
	if _, _, err := s.RedeemPairingCode(ctx, code, "x"); err != ErrInvalidCode {
		t.Errorf("redeeming an expired code: err = %v, want ErrInvalidCode", err)
	}
}

func TestDeviceNameDefaultsWhenEmpty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	code, _ := s.CreatePairingCode(ctx, time.Hour)

	id, token, err := s.RedeemPairingCode(ctx, code, "")
	if err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}
	_, name, ok, err := s.AuthenticateToken(ctx, token)
	if err != nil || !ok {
		t.Fatalf("AuthenticateToken: ok=%v err=%v", ok, err)
	}
	if name == "" {
		t.Error("expected a generated non-empty device name")
	}
	_ = id
}

func TestListDevices(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if devs, err := s.ListDevices(ctx); err != nil || len(devs) != 0 {
		t.Fatalf("ListDevices (empty): devs=%v err=%v", devs, err)
	}

	code1, _ := s.CreatePairingCode(ctx, time.Hour)
	id1, _, err := s.RedeemPairingCode(ctx, code1, "phone")
	if err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}
	code2, _ := s.CreatePairingCode(ctx, time.Hour)
	id2, _, err := s.RedeemPairingCode(ctx, code2, "laptop")
	if err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}

	devs, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devs))
	}
	if devs[0].ID != id2 || devs[0].Name != "laptop" {
		t.Errorf("devs[0] = %+v, want id=%s name=laptop", devs[0], id2)
	}
	if devs[1].ID != id1 || devs[1].Name != "phone" {
		t.Errorf("devs[1] = %+v, want id=%s name=phone", devs[1], id1)
	}
	if devs[0].PairedAt.IsZero() {
		t.Error("expected a non-zero PairedAt")
	}
}
