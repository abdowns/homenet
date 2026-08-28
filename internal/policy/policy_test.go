package policy

import (
	"testing"

	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/schema"
)

const testPolicy = `
filter deny_admin_off_lan(r: HttpRequest) {
  r.path startswith "/admin" and not (r.client in 192.168.1.0/24)
}
filter allow_admin_debug(r: HttpRequest) {
  r.path == "/admin/debug" and r.user == "root"
}
filter public_ci_hooks(r: HttpRequest) {
  r.path startswith "/hooks/"
}
filter block_trackers(q: DnsQuery) {
  q.name matches "*doubleclick*"
}
`

func mustCompile(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p
}

func TestEmptyPolicyDoesNothing(t *testing.T) {
	p := mustCompile(t, "")
	defer p.Close()
	if denied, _ := p.DenyHTTP(schema.HttpRequest{Path: "/admin"}); denied {
		t.Error("empty policy should never deny")
	}
	if blocked, _ := p.BlockDNS(schema.DnsQuery{Name: "doubleclick.net."}); blocked {
		t.Error("empty policy should never block")
	}
	if pub, _ := p.IsPublicHTTP(schema.HttpRequest{}); pub {
		t.Error("empty policy should never mark public")
	}
}

func TestDenyHTTP(t *testing.T) {
	p := mustCompile(t, testPolicy)
	defer p.Close()

	cases := []struct {
		name   string
		req    schema.HttpRequest
		denied bool
	}{
		{"admin off-lan", schema.HttpRequest{Path: "/admin/panel", Client: [4]byte{8, 8, 8, 8}}, true},
		{"admin on-lan", schema.HttpRequest{Path: "/admin/panel", Client: [4]byte{192, 168, 1, 5}}, false},
		{"non-admin", schema.HttpRequest{Path: "/", Client: [4]byte{8, 8, 8, 8}}, false},
		{"admin off-lan but explicitly allowed", schema.HttpRequest{Path: "/admin/debug", User: "root", Client: [4]byte{8, 8, 8, 8}}, false},
	}
	for _, c := range cases {
		denied, rule := p.DenyHTTP(c.req)
		if denied != c.denied {
			t.Errorf("%s: denied = %v, want %v", c.name, denied, c.denied)
		}
		if c.denied && rule != "deny_admin_off_lan" {
			t.Errorf("%s: rule = %q, want deny_admin_off_lan", c.name, rule)
		}
	}
}

func TestIsPublicHTTP(t *testing.T) {
	p := mustCompile(t, testPolicy)
	defer p.Close()
	if pub, rule := p.IsPublicHTTP(schema.HttpRequest{Path: "/hooks/github"}); !pub || rule != "public_ci_hooks" {
		t.Errorf("IsPublicHTTP(/hooks/github) = (%v, %q), want (true, public_ci_hooks)", pub, rule)
	}
	if pub, _ := p.IsPublicHTTP(schema.HttpRequest{Path: "/private"}); pub {
		t.Error("IsPublicHTTP(/private) = true, want false")
	}
}

func TestBlockDNS(t *testing.T) {
	p := mustCompile(t, testPolicy)
	defer p.Close()
	if blocked, rule := p.BlockDNS(schema.DnsQuery{Name: "ads.doubleclick.net."}); !blocked || rule != "block_trackers" {
		t.Errorf("BlockDNS(doubleclick) = (%v, %q), want (true, block_trackers)", blocked, rule)
	}
	if blocked, _ := p.BlockDNS(schema.DnsQuery{Name: "github.com."}); blocked {
		t.Error("BlockDNS(github.com) = true, want false")
	}
}

func TestRuleNames(t *testing.T) {
	p := mustCompile(t, testPolicy)
	defer p.Close()
	names := p.RuleNames()
	if len(names["deny_"]) != 1 || names["deny_"][0] != "deny_admin_off_lan" {
		t.Errorf("deny_ rules = %v", names["deny_"])
	}
	if len(names["allow_"]) != 1 {
		t.Errorf("allow_ rules = %v", names["allow_"])
	}
	if len(names["public_"]) != 1 {
		t.Errorf("public_ rules = %v", names["public_"])
	}
	if len(names["block_"]) != 1 || names["block_"][0] != "block_trackers" {
		t.Errorf("block_ rules = %v", names["block_"])
	}
}

func TestPolicyTest(t *testing.T) {
	p := mustCompile(t, testPolicy)
	defer p.Close()

	httpRows := []schema.HttpRequest{
		{Path: "/admin/x", Client: [4]byte{8, 8, 8, 8}},
		{Path: "/admin/x", Client: [4]byte{8, 8, 8, 9}},
		{Path: "/", Client: [4]byte{8, 8, 8, 8}},
	}
	res := p.TestHTTP(httpRows)
	if res.HTTPTotal != 3 || res.HTTPDenied != 2 {
		t.Errorf("TestHTTP = %+v, want Total=3 Denied=2", res)
	}
	if res.DeniedBy["deny_admin_off_lan"] != 2 {
		t.Errorf("DeniedBy[deny_admin_off_lan] = %d, want 2", res.DeniedBy["deny_admin_off_lan"])
	}

	dnsRows := []schema.DnsQuery{
		{Name: "ads.doubleclick.net."},
		{Name: "github.com."},
	}
	dres := p.TestDNS(dnsRows)
	if dres.DNSTotal != 2 || dres.DNSBlocked != 1 {
		t.Errorf("TestDNS = %+v, want Total=2 Blocked=1", dres)
	}
}

func TestCompileErrorPropagates(t *testing.T) {
	if _, err := Compile("filter x(r: NoSuchSchema) { true }"); err == nil {
		t.Fatal("expected a compile error")
	}
}

// verifies packing stays compatible across separate nql.Program instances
func TestTestHTTPRing(t *testing.T) {
	ringProg, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compiling prelude for the ring: %v", err)
	}
	defer ringProg.Close()
	ring, err := journal.NewRing(ringProg, "HttpRequest", 8, 4)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	defer ring.Close()

	rows := []schema.HttpRequest{
		{Path: "/admin/x", Client: [4]byte{8, 8, 8, 8}},
		{Path: "/admin/x", Client: [4]byte{8, 8, 8, 9}},
		{Path: "/", Client: [4]byte{8, 8, 8, 8}},
	}
	for _, r := range rows {
		ring.Append(func(buf *nql.Buf, i int) { schema.PackHttpRequest(buf, i, r) })
	}

	p := mustCompile(t, testPolicy)
	defer p.Close()
	res := p.TestHTTPRing(ring)
	if res.HTTPTotal != 3 || res.HTTPDenied != 2 {
		t.Errorf("TestHTTPRing = %+v, want Total=3 Denied=2", res)
	}
}
