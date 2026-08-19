package docker

import (
	"context"
	"testing"

	"labnet/internal/proxy"
)

type fakeClient struct {
	polls [][]Container
	n     int
}

func (f *fakeClient) ListContainers(ctx context.Context) ([]Container, error) {
	c := f.polls[f.n]
	if f.n < len(f.polls)-1 {
		f.n++
	}
	return c, nil
}

func TestDiscoveryRegistersAndDeregisters(t *testing.T) {
	fc := &fakeClient{polls: [][]Container{
		{
			{ID: "c1", Name: "app", Running: true, IP: "172.18.0.2",
				Labels: map[string]string{LabelHost: "app.lab"}},
		},
		{
			{ID: "c1", Name: "app", Running: false, IP: "",
				Labels: map[string]string{LabelHost: "app.lab"}},
		},
	}}
	reg := proxy.NewRegistry()
	d := NewDiscovery(fc, reg, 0)

	n, err := d.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 service after poll 1, got %d", n)
	}
	svc, ok := reg.Lookup("app.lab")
	if !ok {
		t.Fatal("app.lab not registered after poll 1")
	}
	if svc.Target.Host != "172.18.0.2:80" {
		t.Errorf("target = %s, want 172.18.0.2:80", svc.Target.Host)
	}

	n, err = d.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce (2): %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 services after poll 2 (container stopped), got %d", n)
	}
	if _, ok := reg.Lookup("app.lab"); ok {
		t.Error("app.lab still registered after its container stopped")
	}
}

func TestDiscoveryIgnoresUnlabeledAndIPlessContainers(t *testing.T) {
	fc := &fakeClient{polls: [][]Container{{
		{ID: "c1", Name: "no-label", Running: true, IP: "172.18.0.3"},
		{ID: "c2", Name: "no-ip", Running: true, Labels: map[string]string{LabelHost: "noip.lab"}},
	}}}
	reg := proxy.NewRegistry()
	d := NewDiscovery(fc, reg, 0)
	n, err := d.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 services, got %d", n)
	}
}
