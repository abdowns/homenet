package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeWriter struct {
	remote  net.Addr
	written *dns.Msg
}

func (f *fakeWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (f *fakeWriter) RemoteAddr() net.Addr        { return f.remote }
func (f *fakeWriter) WriteMsg(m *dns.Msg) error   { f.written = m; return nil }
func (f *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeWriter) Close() error                { return nil }
func (f *fakeWriter) TsigStatus() error           { return nil }
func (f *fakeWriter) TsigTimersOnly(bool)         {}
func (f *fakeWriter) Hijack()                     {}

func newTestHandler(t *testing.T, upstream string) dns.Handler {
	t.Helper()
	h, err := NewHandler(Config{
		Zone:     "lab",
		HostIP:   net.ParseIP("192.168.1.50"),
		Upstream: upstream,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func query(t *testing.T, h dns.Handler, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	w := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5555}}
	h.ServeDNS(w, req)
	if w.written == nil {
		t.Fatalf("no response written for %s", name)
	}
	return w.written
}

func TestAuthoritativeAResolves(t *testing.T) {
	h := newTestHandler(t, "127.0.0.1:1")
	resp := query(t, h, "myapp.lab.", dns.TypeA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("192.168.1.50")) {
		t.Errorf("answer A = %s, want 192.168.1.50", a.A)
	}
}

func TestForwarding(t *testing.T) {
	upstream, err := Listen("127.0.0.1:0", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 9.9.9.9")
		m.Answer = append(m.Answer, rr)
		w.WriteMsg(m)
	}))
	if err != nil {
		t.Fatalf("Listen(upstream): %v", err)
	}
	defer upstream.Shutdown()
	go upstream.Serve()

	srv, err := Listen("127.0.0.1:0", newTestHandler(t, upstream.Addr()))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Shutdown()
	go srv.Serve()
	time.Sleep(50 * time.Millisecond)

	c := new(dns.Client)
	req := new(dns.Msg)
	req.SetQuestion("github.com.", dns.TypeA)
	resp, _, err := c.Exchange(req, srv.Addr())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 forwarded answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("9.9.9.9")) {
		t.Fatalf("forwarded answer = %v, want A 9.9.9.9", resp.Answer[0])
	}
}
