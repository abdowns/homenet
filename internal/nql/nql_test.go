package nql

import (
	"encoding/csv"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
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

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

type weblogRow struct {
	ts           uint64
	client       [4]byte
	method, path string
	status       uint16
	bytes        uint32
	ms           float64
	user, agent  string
}

func parseIP4(t *testing.T, s string) [4]byte {
	t.Helper()
	ip4 := net.ParseIP(s).To4()
	if ip4 == nil {
		t.Fatalf("bad IPv4 %q", s)
	}
	return [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
}

func loadWeblog(t *testing.T) []weblogRow {
	t.Helper()
	f, err := os.Open(filepath.Join(repoRoot(t), "netdb-lang", "examples", "data", "weblog.csv"))
	if err != nil {
		t.Fatalf("opening weblog.csv: %v", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parsing weblog.csv: %v", err)
	}
	var rows []weblogRow
	for _, rec := range records[1:] {
		ts, err := strconv.ParseUint(rec[0], 10, 64)
		if err != nil {
			t.Fatalf("bad ts %q: %v", rec[0], err)
		}
		status, err := strconv.ParseUint(rec[4], 10, 16)
		if err != nil {
			t.Fatalf("bad status %q: %v", rec[4], err)
		}
		bytesv, err := strconv.ParseUint(rec[5], 10, 32)
		if err != nil {
			t.Fatalf("bad bytes %q: %v", rec[5], err)
		}
		ms, err := strconv.ParseFloat(rec[6], 64)
		if err != nil {
			t.Fatalf("bad ms %q: %v", rec[6], err)
		}
		rows = append(rows, weblogRow{
			ts:     ts,
			client: parseIP4(t, rec[1]),
			method: rec[2],
			path:   rec[3],
			status: uint16(status),
			bytes:  uint32(bytesv),
			ms:     ms,
			user:   rec[7],
			agent:  rec[8],
		})
	}
	return rows
}

func packWeblog(t *testing.T, schema *Schema, rows []weblogRow) *Buf {
	t.Helper()
	buf := NewBuf(schema, len(rows))
	for i, r := range rows {
		buf.SetUint(i, "ts", r.ts)
		buf.SetIP4(i, "client", r.client[0], r.client[1], r.client[2], r.client[3])
		buf.SetStr(i, "method", r.method)
		buf.SetStr(i, "path", r.path)
		buf.SetUint(i, "status", uint64(r.status))
		buf.SetUint(i, "bytes", uint64(r.bytes))
		buf.SetF64(i, "ms", r.ms)
		buf.SetStr(i, "user", r.user)
		buf.SetStr(i, "agent", r.agent)
	}
	return buf
}

func compileWeblog(t *testing.T) *Program {
	t.Helper()
	src := mustReadFile(t, filepath.Join(repoRoot(t), "netdb-lang", "examples", "weblog.nql"))
	prog, err := Compile("", src)
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
	rows := loadWeblog(t)
	if len(rows) != 36 {
		t.Fatalf("expected 36 rows, got %d", len(rows))
	}
	buf := packWeblog(t, schema, rows)
	defer buf.Free()

	n := uint64(buf.Len())

	filterWant := map[string]uint64{
		"attack_surface": 6,
		"errors":         7,
	}
	for name, want := range filterWant {
		k, ok := prog.FilterKernels(name)
		if !ok {
			t.Fatalf("filter %q not found", name)
		}
		if got := k.Count(buf.Base(), n); got != want {
			t.Errorf("filter %s: got %d matches, want %d", name, got, want)
		}
	}

	queryWant := map[string]uint64{
		"slow_api":      8,
		"auth_failures": 4,
		"big_responses": 3,
	}
	for name, want := range queryWant {
		k, ok := prog.QueryKernels(name)
		if !ok {
			t.Fatalf("query %q not found", name)
		}
		if !k.HasCollect() {
			t.Fatalf("query %s: expected a where clause", name)
		}
		if got := k.Count(buf.Base(), n); got != want {
			t.Errorf("query %s: got %d matches, want %d", name, got, want)
		}
		idx := make([]uint64, n)
		got := k.Collect(buf.Base(), n, idx)
		if got != want {
			t.Errorf("query %s: Collect returned %d, want %d", name, got, want)
		}
	}
}

func TestJITMatchesInterpreter(t *testing.T) {
	prog := compileWeblog(t)
	schema, _ := prog.Schema("LogEntry")
	rows := loadWeblog(t)
	buf := packWeblog(t, schema, rows)
	defer buf.Free()

	for _, name := range []string{"attack_surface", "errors"} {
		k, ok := prog.FilterKernels(name)
		if !ok {
			t.Fatalf("filter %q not found", name)
		}
		for i := 0; i < buf.Len(); i++ {
			jit := k.Pred(buf.Rec(i))
			interp, err := prog.EvalFilterInterp(name, buf.Rec(i))
			if err != nil {
				t.Fatalf("EvalFilterInterp(%s): %v", name, err)
			}
			if jit != interp {
				t.Errorf("filter %s record %d: JIT=%v interpreter=%v", name, i, jit, interp)
			}
		}
	}
}

// run with -race
func TestConcurrentKernelCalls(t *testing.T) {
	prog := compileWeblog(t)
	schema, _ := prog.Schema("LogEntry")
	rows := loadWeblog(t)
	buf := packWeblog(t, schema, rows)
	defer buf.Free()

	k, ok := prog.FilterKernels("attack_surface")
	if !ok {
		t.Fatal("filter attack_surface not found")
	}
	n := uint64(buf.Len())

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if got := k.Count(buf.Base(), n); got != 6 {
					errs <- "unexpected concurrent count"
				}
				for r := 0; r < buf.Len(); r++ {
					_ = k.Pred(buf.Rec(r))
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestCompileError(t *testing.T) {
	_, err := Compile("", "filter x(p: NoSuchSchema) { true }")
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, ok := err.(*CompileError); !ok {
		t.Fatalf("expected *CompileError, got %T", err)
	}
}

func TestFilters(t *testing.T) {
	prog := compileWeblog(t)
	filters := prog.Filters()
	byName := map[string]FilterInfo{}
	for _, f := range filters {
		byName[f.Name] = f
	}
	if len(filters) != 2 {
		t.Fatalf("expected 2 filters, got %d: %+v", len(filters), filters)
	}
	for _, name := range []string{"attack_surface", "errors"} {
		fi, ok := byName[name]
		if !ok {
			t.Errorf("filter %q not found in Filters()", name)
			continue
		}
		if fi.SchemaName != "LogEntry" {
			t.Errorf("filter %s: schema = %q, want LogEntry", name, fi.SchemaName)
		}
	}
}

func TestPreludeLineAdjustment(t *testing.T) {
	prelude := "schema P { x: u32 }\nconst FOO = 1;\n"
	_, err := Compile(prelude, "filter y(p: P) { nosuchvar }")
	if err == nil {
		t.Fatal("expected an error")
	}
	ce, ok := err.(*CompileError)
	if !ok {
		t.Fatalf("expected *CompileError, got %T", err)
	}
	const want = "1:"
	if len(ce.Message) < len(want) || ce.Message[:len(want)] != want {
		t.Errorf("expected error to be adjusted to line 1 of user_src, got: %s", ce.Message)
	}
}
