package journal

import (
	"testing"

	"labnet/internal/nql"
	"labnet/internal/schema"
)

func TestRingAppendAndQuery(t *testing.T) {
	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compiling prelude: %v", err)
	}
	defer prog.Close()

	ring, err := NewRing(prog, "DnsQuery", 4)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	defer ring.Close()

	names := []string{"a.lab", "b.lab", "blocked.ads.example", "c.lab", "blocked.tracker.example"}
	for i, name := range names {
		q := schema.DnsQuery{
			TS:      uint64(1000 + i),
			Client:  [4]byte{10, 0, 0, byte(i + 1)},
			Name:    name,
			QType:   1,
			Blocked: i == 2 || i == 4,
		}
		ring.Append(func(buf *nql.Buf, j int) { schema.PackDnsQuery(buf, j, q) })
	}

	if got := ring.Len(); got != 5 {
		t.Fatalf("Len: got %d, want 5", got)
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

	var first string
	for _, fv := range rows[0] {
		if fv.Name == "name" {
			first = fv.Value.(string)
		}
	}
	if first != "blocked.tracker.example" {
		t.Errorf("rows[0].name = %q, want blocked.tracker.example", first)
	}
}

func TestRingEviction(t *testing.T) {
	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		t.Fatalf("compiling prelude: %v", err)
	}
	defer prog.Close()

	ring, err := NewRing(prog, "DnsQuery", 2)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	defer ring.Close()

	for i := 0; i < 10; i++ {
		q := schema.DnsQuery{TS: uint64(i), Name: "x"}
		ring.Append(func(buf *nql.Buf, j int) { schema.PackDnsQuery(buf, j, q) })
	}
	if got := ring.Len(); got != numSegments*2 {
		t.Fatalf("Len after eviction: got %d, want %d", got, numSegments*2)
	}

	rows, _, err := ring.Query("true", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != numSegments*2 {
		t.Fatalf("expected %d surviving rows, got %d", numSegments*2, len(rows))
	}
}
