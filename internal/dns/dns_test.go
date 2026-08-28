package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/schema"
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

func newRing(t *testing.T) *journal.Ring {
	t.Helper()
	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compile prelude: %v", err)
	}
	t.Cleanup(func() { prog.Close() })
	ring, err := journal.NewRing(prog, "DnsQuery", 16, 4)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	t.Cleanup(ring.Close)
	return ring
}

func TestAuthoritativeAResolves(t *testing.T) {
	ring := newRing(t)
	h, err := NewHandler(Config{
		Zone:     "lab",
		HostIP:   net.ParseIP("192.168.1.50"),
		Upstream: "127.0.0.1:1",
		Journal:  ring,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("myapp.lab.", dns.TypeA)
	w := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5555}}
	h.ServeDNS(w, req)

	if w.written == nil {
		t.Fatal("no response written")
	}
	if w.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", w.written.Rcode)
	}
	if len(w.written.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.written.Answer))
	}
	a, ok := w.written.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", w.written.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("192.168.1.50")) {
		t.Errorf("answer A = %s, want 192.168.1.50", a.A)
	}

	if got := ring.Len(); got != 1 {
		t.Fatalf("journal Len = %d, want 1", got)
	}
	rows, _, err := ring.Query("name == \"myapp.lab.\" and not upstream", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 journaled row, got %d", len(rows))
	}
}

func TestPolicyBlocks(t *testing.T) {
	ring := newRing(t)
	h, err := NewHandler(Config{
		Zone:     "lab",
		HostIP:   net.ParseIP("192.168.1.50"),
		Upstream: "127.0.0.1:1",
		Journal:  ring,
		Policy: func(q schema.DnsQuery) bool {
			return q.Name == "blocked.lab."
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("blocked.lab.", dns.TypeA)
	w := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5555}}
	h.ServeDNS(w, req)

	if w.written.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", w.written.Rcode)
	}
	rows, _, err := ring.Query("blocked", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 blocked row journaled, got %d", len(rows))
	}
}

// regression test: block rules target ad/tracker domains outside our zone,
// so this must not require *.lab to fire
func TestPolicyBlocksOutOfZone(t *testing.T) {
	ring := newRing(t)
	h, err := NewHandler(Config{
		Zone:     "lab",
		HostIP:   net.ParseIP("192.168.1.50"),
		Upstream: "127.0.0.1:1", // must not be reached, blocking short circuits first
		Journal:  ring,
		Policy: func(q schema.DnsQuery) bool {
			return q.Name == "ads.doubleclick.net."
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("ads.doubleclick.net.", dns.TypeA)
	w := &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5555}}
	h.ServeDNS(w, req)

	if w.written.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", w.written.Rcode)
	}
	rows, _, err := ring.Query(`blocked and not upstream`, 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 blocked (and not forwarded upstream) row journaled, got %d", len(rows))
	}
}

func TestForwarding(t *testing.T) {
	upstream, err := Listen("127.0.0.1:0", staticAnswerHandler(t, "9.9.9.9"))
	if err != nil {
		t.Fatalf("Listen(upstream): %v", err)
	}
	defer upstream.Shutdown()
	go upstream.Serve()

	ring := newRing(t)
	h, err := NewHandler(Config{
		Zone:     "lab",
		HostIP:   net.ParseIP("192.168.1.50"),
		Upstream: upstream.Addr(),
		Journal:  ring,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	srv, err := Listen("127.0.0.1:0", h)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Shutdown()
	go srv.Serve()
	waitForServer(t, srv.Addr())

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

	rows, _, err := ring.Query("upstream", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 upstream-forwarded row journaled, got %d", len(rows))
	}
}

func staticAnswerHandler(t *testing.T, ip string) dns.Handler {
	t.Helper()
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 1 && r.Question[0].Qtype == dns.TypeA {
			rr, err := dns.NewRR(r.Question[0].Name + " 60 IN A " + ip)
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		w.WriteMsg(m)
	})
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("udp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s never became reachable", addr)
}
