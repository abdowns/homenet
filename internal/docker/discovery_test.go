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
	if f.n >= len(f.polls) {
		return f.polls[len(f.polls)-1], nil
	}
	c := f.polls[f.n]
	f.n++
	return c, nil
}
func (f *fakeClient) EnsureNetwork(ctx context.Context, name string) error        { return nil }
func (f *fakeClient) BuildImage(ctx context.Context, dir, tag string) error       { return nil }
func (f *fakeClient) RunContainer(ctx context.Context, s RunSpec) (string, error) { return "", nil }
func (f *fakeClient) StopAndRemove(ctx context.Context, name string) error        { return nil }

func TestDiscoveryRegistersAndDeregisters(t *testing.T) {
	fc := &fakeClient{polls: [][]Container{
		{
			{ID: "c1", Name: "app", Running: true, HostPort: "32768",
				Labels: map[string]string{LabelHost: "app.lab"}},
		},
		{
			{ID: "c1", Name: "app", Running: false, HostPort: "",
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
	if svc.Target.Host != "127.0.0.1:32768" {
		t.Errorf("target = %s, want 127.0.0.1:32768", svc.Target.Host)
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

func TestDiscoveryHonorsPortLabel(t *testing.T) {
	fc := &fakeClient{polls: [][]Container{{
		{ID: "c1", Name: "vite", Running: true, HostPort: "40001",
			Labels: map[string]string{LabelHost: "vite.lab", LabelPort: "5173"}},
	}}}
	reg := proxy.NewRegistry()
	d := NewDiscovery(fc, reg, 0)
	if _, err := d.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	svc, ok := reg.Lookup("vite.lab")
	if !ok {
		t.Fatal("vite.lab not registered")
	}
	if svc.Target.Host != "127.0.0.1:40001" {
		t.Errorf("target = %s, want 127.0.0.1:40001", svc.Target.Host)
	}
}

func TestDiscoveryIgnoresUnlabeledAndIPlessContainers(t *testing.T) {
	fc := &fakeClient{polls: [][]Container{{
		{ID: "c1", Name: "no-label", Running: true, HostPort: "40002"},
		{ID: "c2", Name: "no-port", Running: true, Labels: map[string]string{LabelHost: "noip.lab"}},
		{ID: "c3", Name: "not-running", Running: false, HostPort: "40003",
			Labels: map[string]string{LabelHost: "stopped.lab"}},
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
	if len(reg.List()) != 0 {
		t.Fatalf("expected empty registry, got %d entries", len(reg.List()))
	}
}
