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

func TestRedeemPairingCode(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	code, err := s.CreatePairingCode(ctx, time.Hour)
	if err != nil {
		t.Fatalf("CreatePairingCode: %v", err)
	}

	token, err := s.RedeemPairingCode(ctx, code, "phone")
	if err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty token")
	}

	if _, err := s.RedeemPairingCode(ctx, code, "another-device"); err != ErrInvalidCode {
		t.Errorf("re-redeeming a used code: err = %v, want ErrInvalidCode", err)
	}

	name, ok, err := s.AuthenticateToken(ctx, token)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if !ok || name != "phone" {
		t.Errorf("AuthenticateToken = (%q, %v), want (phone, true)", name, ok)
	}
}

func TestRedeemExpiredCode(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	code, err := s.CreatePairingCode(ctx, -time.Second) // already expired
	if err != nil {
		t.Fatalf("CreatePairingCode: %v", err)
	}
	if _, err := s.RedeemPairingCode(ctx, code, "x"); err != ErrInvalidCode {
		t.Errorf("redeeming an expired code: err = %v, want ErrInvalidCode", err)
	}
}

func TestListDevices(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	code, _ := s.CreatePairingCode(ctx, time.Hour)
	if _, err := s.RedeemPairingCode(ctx, code, "phone"); err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}

	devs, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 1 || devs[0].Name != "phone" {
		t.Errorf("ListDevices = %+v, want a single device named phone", devs)
	}
}
