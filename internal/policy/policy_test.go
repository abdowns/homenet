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
filter alert_slow(r: HttpRequest) {
  r.ms > 1000.0
}
filter block_trackers(q: DnsQuery) {
  q.name matches "*doubleclick*"
}
filter alert_dns_flood(q: DnsQuery) {
  q.name == "flood.example."
}
filter alert_bruteforce(e: AuthEvent) {
  not e.ok and e.kind == "password"
}
filter scratch_not_a_policy_rule(r: HttpRequest) {
  true
}
`

func mustCompile(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestEmptyPolicyDoesNothing(t *testing.T) {
	p := mustCompile(t, "")
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

	cases := []struct {
		name   string
		req    schema.HttpRequest
		denied bool
		rule   string
	}{
		{"admin off-lan", schema.HttpRequest{Path: "/admin/panel", Client: [4]byte{8, 8, 8, 8}}, true, "deny_admin_off_lan"},
		{"admin on-lan", schema.HttpRequest{Path: "/admin/panel", Client: [4]byte{192, 168, 1, 5}}, false, ""},
		{"non-admin", schema.HttpRequest{Path: "/", Client: [4]byte{8, 8, 8, 8}}, false, ""},
		{"admin off-lan but explicitly allowed", schema.HttpRequest{Path: "/admin/debug", User: "root", Client: [4]byte{8, 8, 8, 8}}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			denied, rule := p.DenyHTTP(c.req)
			if denied != c.denied {
				t.Errorf("denied = %v, want %v", denied, c.denied)
			}
			if c.denied && rule != c.rule {
				t.Errorf("rule = %q, want %q", rule, c.rule)
			}
		})
	}
}

func TestIsPublicHTTP(t *testing.T) {
	p := mustCompile(t, testPolicy)
	if pub, rule := p.IsPublicHTTP(schema.HttpRequest{Path: "/hooks/github"}); !pub || rule != "public_ci_hooks" {
		t.Errorf("IsPublicHTTP(/hooks/github) = (%v, %q), want (true, public_ci_hooks)", pub, rule)
	}
	if pub, _ := p.IsPublicHTTP(schema.HttpRequest{Path: "/private"}); pub {
		t.Error("IsPublicHTTP(/private) = true, want false")
	}
}

func TestBlockDNS(t *testing.T) {
	p := mustCompile(t, testPolicy)
	if blocked, rule := p.BlockDNS(schema.DnsQuery{Name: "ads.doubleclick.net."}); !blocked || rule != "block_trackers" {
		t.Errorf("BlockDNS(doubleclick) = (%v, %q), want (true, block_trackers)", blocked, rule)
	}
	if blocked, _ := p.BlockDNS(schema.DnsQuery{Name: "github.com."}); blocked {
		t.Error("BlockDNS(github.com) = true, want false")
	}
}

func TestAlerts(t *testing.T) {
	p := mustCompile(t, testPolicy)

	if got := p.AlertsHTTP(schema.HttpRequest{MS: 2500}); len(got) != 1 || got[0] != "alert_slow" {
		t.Errorf("AlertsHTTP(slow) = %v, want [alert_slow]", got)
	}
	if got := p.AlertsHTTP(schema.HttpRequest{MS: 5}); len(got) != 0 {
		t.Errorf("AlertsHTTP(fast) = %v, want none", got)
	}
	if got := p.AlertsDNS(schema.DnsQuery{Name: "flood.example."}); len(got) != 1 || got[0] != "alert_dns_flood" {
		t.Errorf("AlertsDNS = %v, want [alert_dns_flood]", got)
	}
	if got := p.AlertsAuth(schema.AuthEvent{OK: false, Kind: "password"}); len(got) != 1 || got[0] != "alert_bruteforce" {
		t.Errorf("AlertsAuth(failed password) = %v, want [alert_bruteforce]", got)
	}
	if got := p.AlertsAuth(schema.AuthEvent{OK: true, Kind: "password"}); len(got) != 0 {
		t.Errorf("AlertsAuth(ok) = %v, want none", got)
	}
}

func TestUnrecognizedPrefixHasNoEffect(t *testing.T) {
	p := mustCompile(t, testPolicy)
	names := p.RuleNames()
	for _, category := range names {
		for _, n := range category {
			if n == "scratch_not_a_policy_rule" {
				t.Fatal("scratch_not_a_policy_rule should not be wired to any category")
			}
		}
	}
}

func TestRuleNames(t *testing.T) {
	p := mustCompile(t, testPolicy)
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
	if len(names["block_"]) != 1 {
		t.Errorf("block_ rules = %v", names["block_"])
	}
	if len(names["alert_"]) != 3 {
		t.Errorf("alert_ rules = %v, want 3 (one per schema)", names["alert_"])
	}
}

func TestPolicyTest(t *testing.T) {
	p := mustCompile(t, testPolicy)

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
	res := p.TestHTTPRing(ring)
	if res.HTTPTotal != 3 || res.HTTPDenied != 2 {
		t.Errorf("TestHTTPRing = %+v, want Total=3 Denied=2", res)
	}
	if res.DeniedBy["deny_admin_off_lan"] != 2 {
		t.Errorf("DeniedBy[deny_admin_off_lan] = %d, want 2", res.DeniedBy["deny_admin_off_lan"])
	}
}
