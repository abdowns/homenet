package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"labnet/internal/auth"
	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/policy"
	"labnet/internal/proxy"
	"labnet/internal/schema"
)

func TestServerAndClient(t *testing.T) {
	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compile prelude: %v", err)
	}
	defer prog.Close()

	dnsRing, err := journal.NewRing(prog, "DnsQuery", 16, 4)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	defer dnsRing.Close()

	for i, name := range []string{"a.lab.", "blocked.example.", "b.lab."} {
		q := schema.DnsQuery{TS: uint64(i), Name: name, Blocked: name == "blocked.example."}
		dnsRing.Append(func(buf *nql.Buf, j int) { schema.PackDnsQuery(buf, j, q) })
	}

	mux := http.NewServeMux()
	svc := Services{Registry: proxy.NewRegistry(), DockerNetwork: "labnet"}
	NewServer("lab", prog, map[string]*journal.Ring{"DnsQuery": dnsRing}, svc, PolicyDeps{}, AuthDeps{}).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL)

	resp, err := client.Query(QueryRequest{Schema: "DnsQuery", Predicate: "blocked"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Matched != 1 || len(resp.Rows) != 1 {
		t.Fatalf("expected 1 matched row, got Matched=%d rows=%d", resp.Matched, len(resp.Rows))
	}
	if resp.Scanned != 3 {
		t.Errorf("Scanned = %d, want 3", resp.Scanned)
	}

	if _, err := client.Query(QueryRequest{Schema: "NoSuchSchema", Predicate: "true"}); err == nil {
		t.Fatal("expected an error for an unknown schema")
	}
	if _, err := client.Query(QueryRequest{Schema: "DnsQuery", Predicate: "not a valid predicate((("}); err == nil {
		t.Fatal("expected an error for a bad predicate")
	}

	status, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Zone != "lab" {
		t.Errorf("Zone = %q, want lab", status.Zone)
	}
	if got := status.Ringlen["DnsQuery"]; got.Len != 3 || got.Total != 3 {
		t.Errorf("Ringlen[DnsQuery] = %+v, want Len=3 Total=3", got)
	}
	if len(status.Schemas["DnsQuery"]) == 0 {
		t.Error("expected DnsQuery fields in Schemas")
	}
}

func TestPolicyAndDeviceEndpoints(t *testing.T) {
	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compile prelude: %v", err)
	}
	defer prog.Close()

	httpRing, err := journal.NewRing(prog, "HttpRequest", 16, 4)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	defer httpRing.Close()
	httpRing.Append(func(buf *nql.Buf, i int) {
		schema.PackHttpRequest(buf, i, schema.HttpRequest{Path: "/admin", Service: "admin"})
	})
	httpRing.Append(func(buf *nql.Buf, i int) {
		schema.PackHttpRequest(buf, i, schema.HttpRequest{Path: "/", Service: "app"})
	})

	policyMgr, err := policy.NewManager(filepath.Join(t.TempDir(), "policy.nql"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	alertLog := policy.NewAlertLog(10)
	alertLog.Add(policy.Alert{TS: 1, Schema: "HttpRequest", Rule: "alert_admin", Summary: "test"})

	authStore, err := auth.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("auth.Open: %v", err)
	}
	defer authStore.Close()

	mux := http.NewServeMux()
	NewServer("lab", prog, map[string]*journal.Ring{"HttpRequest": httpRing},
		Services{Registry: proxy.NewRegistry()},
		PolicyDeps{Manager: policyMgr, Alerts: alertLog},
		AuthDeps{Store: authStore},
	).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := NewClient(srv.URL)

	checkResp, err := client.PolicyCheck(`filter deny_admin(r: HttpRequest) { r.service == "admin" }`)
	if err != nil {
		t.Fatalf("PolicyCheck: %v", err)
	}
	if !checkResp.OK || len(checkResp.Rules["deny_"]) != 1 {
		t.Errorf("PolicyCheck = %+v, want OK with 1 deny_ rule", checkResp)
	}
	if badResp, _ := client.PolicyCheck("not valid nql {{{"); badResp == nil || badResp.OK {
		t.Errorf("PolicyCheck(invalid) = %+v, want OK=false", badResp)
	}

	testResp, err := client.PolicyTest(`filter deny_admin(r: HttpRequest) { r.service == "admin" }`)
	if err != nil {
		t.Fatalf("PolicyTest: %v", err)
	}
	if testResp.HTTP.Total != 2 || testResp.HTTP.Matched != 1 {
		t.Errorf("PolicyTest.HTTP = %+v, want Total=2 Matched=1", testResp.HTTP)
	}

	applyResp, err := client.PolicyApply(`filter deny_admin(r: HttpRequest) { r.service == "admin" }`)
	if err != nil {
		t.Fatalf("PolicyApply: %v", err)
	}
	if !applyResp.OK {
		t.Fatalf("PolicyApply not OK: %+v", applyResp)
	}
	statusResp, err := client.PolicyStatus()
	if err != nil {
		t.Fatalf("PolicyStatus: %v", err)
	}
	if statusResp.Source != `filter deny_admin(r: HttpRequest) { r.service == "admin" }` {
		t.Errorf("PolicyStatus.Source = %q", statusResp.Source)
	}
	if len(statusResp.Rules["deny_"]) != 1 {
		t.Errorf("PolicyStatus.Rules = %+v", statusResp.Rules)
	}

	alerts, err := client.Alerts()
	if err != nil {
		t.Fatalf("Alerts: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Rule != "alert_admin" {
		t.Errorf("Alerts = %+v, want one alert_admin", alerts)
	}

	devices, err := client.Devices()
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(devices))
	}
	pc, err := client.PairCode(0)
	if err != nil {
		t.Fatalf("PairCode: %v", err)
	}
	if len(pc.Code) != 6 {
		t.Fatalf("PairCode.Code = %q, want 6 digits", pc.Code)
	}
	if _, _, err := authStore.RedeemPairingCode(t.Context(), pc.Code, "test-device"); err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}
	devices, err = client.Devices()
	if err != nil {
		t.Fatalf("Devices (after pairing): %v", err)
	}
	if len(devices) != 1 || devices[0].Name != "test-device" {
		t.Fatalf("Devices = %+v, want one test-device", devices)
	}
}
