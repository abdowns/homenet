package journal

import (
	"testing"

	"labnet/internal/nql"
	"labnet/internal/schema"
)

func compilePrelude(t *testing.T) *nql.Program {
	t.Helper()
	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compiling prelude: %v", err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog
}

func TestRingAppendAndQuery(t *testing.T) {
	prog := compilePrelude(t)
	ring, err := NewRing(prog, "DnsQuery", 4, 2)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	defer ring.Close()

	names := []string{"a.lab", "b.lab", "blocked.ads.example", "c.lab", "blocked.tracker.example"}
	for i, name := range names {
		q := schema.DnsQuery{
			TS:      uint64(1000 + i),
			Client:  [4]byte{10, 0, 0, byte(i + 1)},
			Device:  "phone",
			Name:    name,
			QType:   1,
			RCode:   0,
			Blocked: i == 2 || i == 4,
			MS:      1.5,
		}
		ring.Append(func(buf *nql.Buf, j int) { schema.PackDnsQuery(buf, j, q) })
	}

	if got := ring.Len(); got != 5 {
		t.Fatalf("Len: got %d, want 5", got)
	}
	if got := ring.Total(); got != 5 {
		t.Fatalf("Total: got %d, want 5", got)
	}

	rows, stats, err := ring.Query("blocked", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 blocked rows, got %d", len(rows))
	}
	if stats.Scanned != 5 || stats.Matched != 2 {
		t.Errorf("stats = %+v, want Scanned=5 Matched=2", stats)
	}
	nameOf := func(r Row) string {
		for _, fv := range r {
			if fv.Name == "name" {
				return fv.Value.(string)
			}
		}
		t.Fatal("row has no name field")
		return ""
	}
	if got := nameOf(rows[0]); got != "blocked.tracker.example" {
		t.Errorf("newest-first order: rows[0].name = %q, want blocked.tracker.example", got)
	}
	if got := nameOf(rows[1]); got != "blocked.ads.example" {
		t.Errorf("newest-first order: rows[1].name = %q, want blocked.ads.example", got)
	}

	clientOf := func(r Row) string {
		for _, fv := range r {
			if fv.Name == "client" {
				return fv.Value.(string)
			}
		}
		t.Fatal("row has no client field")
		return ""
	}
	if got := clientOf(rows[0]); got != "10.0.0.5" {
		t.Errorf("client = %q, want 10.0.0.5", got)
	}
}

func TestRingEviction(t *testing.T) {
	prog := compilePrelude(t)
	ring, err := NewRing(prog, "DnsQuery", 2, 2)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	defer ring.Close()

	for i := 0; i < 10; i++ {
		q := schema.DnsQuery{TS: uint64(i), Name: "x"}
		ring.Append(func(buf *nql.Buf, j int) { schema.PackDnsQuery(buf, j, q) })
	}
	if got := ring.Len(); got != 4 {
		t.Fatalf("Len after eviction: got %d, want 4 (2 segments * segCap 2)", got)
	}
	if got := ring.Total(); got != 10 {
		t.Fatalf("Total: got %d, want 10", got)
	}

	rows, _, err := ring.Query("true", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("expected 4 surviving rows, got %d", len(rows))
	}
	// oldest 6 (ts 0..5) evicted, survivors are 6..9
	seen := map[uint64]bool{}
	for _, r := range rows {
		for _, fv := range r {
			if fv.Name == "ts" {
				seen[fv.Value.(uint64)] = true
			}
		}
	}
	for want := uint64(6); want <= 9; want++ {
		if !seen[want] {
			t.Errorf("expected surviving record with ts=%d, not found", want)
		}
	}
}

func TestRingCount(t *testing.T) {
	prog := compilePrelude(t)
	ring, err := NewRing(prog, "DnsQuery", 8, 4)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	defer ring.Close()

	for i := 0; i < 20; i++ {
		q := schema.DnsQuery{TS: uint64(i), QType: uint16(1 + i%2)}
		ring.Append(func(buf *nql.Buf, j int) { schema.PackDnsQuery(buf, j, q) })
	}

	filterProg, err := nql.Compile(schema.Prelude, "filter isA(r: DnsQuery) { qtype == 1 }")
	if err != nil {
		t.Fatalf("compile filter: %v", err)
	}
	defer filterProg.Close()
	k, ok := filterProg.FilterKernels("isA")
	if !ok {
		t.Fatal("filter isA not found")
	}
	if got := ring.Count(k); got != 10 {
		t.Errorf("Count: got %d, want 10", got)
	}
}
