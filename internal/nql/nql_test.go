package nql

import (
	"encoding/csv"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func loadWeblog(t *testing.T, schema *Schema) *Buf {
	t.Helper()
	f, err := os.Open(filepath.Join(repoRoot(t), "netdb-lang", "examples", "data", "weblog.csv"))
	if err != nil {
		t.Fatalf("opening weblog.csv: %v", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("parsing weblog.csv: %v", err)
	}
	records = records[1:]
	buf := NewBuf(schema, len(records))
	for i, rec := range records {
		ts, _ := strconv.ParseUint(rec[0], 10, 64)
		ip4 := net.ParseIP(rec[1]).To4()
		if ip4 == nil {
			t.Fatalf("bad IPv4 %q", rec[1])
		}
		status, _ := strconv.ParseUint(rec[4], 10, 16)
		bytesv, _ := strconv.ParseUint(rec[5], 10, 32)
		ms, _ := strconv.ParseFloat(rec[6], 64)
		buf.SetUint(i, "ts", ts)
		buf.SetIP4(i, "client", ip4[0], ip4[1], ip4[2], ip4[3])
		buf.SetStr(i, "method", rec[2])
		buf.SetStr(i, "path", rec[3])
		buf.SetUint(i, "status", status)
		buf.SetUint(i, "bytes", bytesv)
		buf.SetF64(i, "ms", ms)
		buf.SetStr(i, "user", rec[7])
		buf.SetStr(i, "agent", rec[8])
	}
	return buf
}

func compileWeblog(t *testing.T) *Program {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "netdb-lang", "examples", "weblog.nql"))
	if err != nil {
		t.Fatalf("reading weblog.nql: %v", err)
	}
	prog, err := Compile(string(src))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog
}

// expected counts captured by hand from the cli; re-verify if
// examples/weblog.nql or its data change
func TestWeblogCounts(t *testing.T) {
	prog := compileWeblog(t)
	schema, ok := prog.Schema("LogEntry")
	if !ok {
		t.Fatal("LogEntry schema not found")
	}
	buf := loadWeblog(t, schema)
	defer buf.Free()
	if buf.Len() != 36 {
		t.Fatalf("expected 36 rows, got %d", buf.Len())
	}

	n := uint64(buf.Len())

	for name, want := range map[string]uint64{"attack_surface": 6, "errors": 7} {
		k, ok := prog.FilterKernels(name)
		if !ok {
			t.Fatalf("filter %q not found", name)
		}
		if got := k.Count(buf.Base(), n); got != want {
			t.Errorf("filter %s: got %d matches, want %d", name, got, want)
		}
	}

	for name, want := range map[string]uint64{"slow_api": 8, "auth_failures": 4, "big_responses": 3} {
		k, ok := prog.QueryKernels(name)
		if !ok {
			t.Fatalf("query %q not found", name)
		}
		if got := k.Count(buf.Base(), n); got != want {
			t.Errorf("query %s: got %d matches, want %d", name, got, want)
		}
	}
}

func TestCompileError(t *testing.T) {
	_, err := Compile("filter x(p: NoSuchSchema) { true }")
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, ok := err.(*CompileError); !ok {
		t.Fatalf("expected *CompileError, got %T", err)
	}
}
