package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"labnet/internal/journal"
	"labnet/internal/nql"
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

	const bigTS = uint64(1)<<63 + 7
	for i, name := range []string{"a.lab.", "blocked.example.", "b.lab."} {
		ts := uint64(i)
		if name == "blocked.example." {
			ts = bigTS
		}
		q := schema.DnsQuery{TS: ts, Name: name, Blocked: name == "blocked.example."}
		dnsRing.Append(func(buf *nql.Buf, j int) { schema.PackDnsQuery(buf, j, q) })
	}

	mux := http.NewServeMux()
	svc := Services{Registry: proxy.NewRegistry(), DockerNetwork: "labnet"}
	NewServer("lab", prog, map[string]*journal.Ring{"DnsQuery": dnsRing}, svc).Register(mux)
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
	if got := fmt.Sprint(resp.Rows[0]["ts"]); got != strconv.FormatUint(bigTS, 10) {
		t.Errorf("row ts = %s, want %d (u64 precision lost)", got, bigTS)
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
