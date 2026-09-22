package journal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
	"unsafe"

	"labnet/internal/nql"
	"labnet/internal/schema"
)

type FieldValue struct {
	Name  string
	Value any
}

type Row []FieldValue

func (r Row) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, fv := range r {
		if i > 0 {
			buf.WriteByte(',')
		}
		nameJSON, err := json.Marshal(fv.Name)
		if err != nil {
			return nil, err
		}
		buf.Write(nameJSON)
		buf.WriteByte(':')
		valJSON, err := json.Marshal(fv.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(valJSON)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// token stream keeps field order; json.number avoids float64 precision
// loss on large u64 values like a millisecond timestamp
func (r *Row) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("journal: Row: expected a JSON object, got %v", tok)
	}
	var out Row
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("journal: Row: expected a string key, got %v", keyTok)
		}
		var val any
		if err := dec.Decode(&val); err != nil {
			return err
		}
		out = append(out, FieldValue{Name: key, Value: val})
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	*r = out
	return nil
}

type QueryStats struct {
	CompileMS float64
	ScanMS    float64
	Scanned   uint64
	Matched   uint64
}

type segment struct {
	buf   *nql.Buf
	count int
}

// safe for concurrent use
type Ring struct {
	mu         sync.RWMutex
	schemaName string
	sch        *nql.Schema
	segCap     int
	maxSegs    int
	segs       []*segment // oldest first
	total      uint64
}

func NewRing(prog *nql.Program, schemaName string, segCap, maxSegs int) (*Ring, error) {
	sch, ok := prog.Schema(schemaName)
	if !ok {
		return nil, fmt.Errorf("journal: no such schema %q", schemaName)
	}
	if segCap < 1 || maxSegs < 1 {
		return nil, fmt.Errorf("journal: segCap and maxSegs must be >= 1")
	}
	return &Ring{schemaName: schemaName, sch: sch, segCap: segCap, maxSegs: maxSegs}, nil
}

func (r *Ring) Append(fill func(buf *nql.Buf, i int)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.segs) == 0 || r.segs[len(r.segs)-1].count >= r.segCap {
		r.segs = append(r.segs, &segment{buf: nql.NewBuf(r.sch, r.segCap)})
		if len(r.segs) > r.maxSegs {
			r.segs[0].buf.Free()
			r.segs = r.segs[1:]
		}
	}
	seg := r.segs[len(r.segs)-1]
	fill(seg.buf, seg.count)
	seg.count++
	r.total++
}

func (r *Ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, s := range r.segs {
		n += s.count
	}
	return n
}

func (r *Ring) Total() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.total
}

func (r *Ring) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.segs {
		s.buf.Free()
	}
	r.segs = nil
}

func (r *Ring) Count(k nql.Kernels) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var total uint64
	for _, s := range r.segs {
		total += k.Count(s.buf.Base(), uint64(s.count))
	}
	return total
}

// fn must not retain rec past the call: a concurrent append can free the
// segment. must not call back into ring.
func (r *Ring) Scan(fn func(rec unsafe.Pointer)) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.segs {
		for i := 0; i < s.count; i++ {
			fn(s.buf.Rec(i))
		}
	}
}

func (r *Ring) Query(predicate string, limit int) ([]Row, QueryStats, error) {
	var stats QueryStats

	t0 := time.Now()
	src := fmt.Sprintf("filter __adhoc(r: %s) {\n%s\n}\n", r.schemaName, predicate)
	prog, err := nql.Compile(schema.Prelude, src)
	if err != nil {
		return nil, stats, err
	}
	defer prog.Close()
	stats.CompileMS = msSince(t0)

	k, ok := prog.FilterKernels("__adhoc")
	if !ok {
		return nil, stats, fmt.Errorf("journal: internal error: __adhoc filter missing after compile")
	}

	t1 := time.Now()
	r.mu.RLock()
	var rows []Row
	for _, s := range r.segs {
		n := uint64(s.count)
		stats.Scanned += n
		if n == 0 {
			continue
		}
		idx := make([]uint64, n)
		got := k.Collect(s.buf.Base(), n, idx)
		for _, i := range idx[:got] {
			rows = append(rows, decodeRow(r.sch, s.buf.Rec(int(i))))
		}
	}
	r.mu.RUnlock()
	stats.ScanMS = msSince(t1)
	stats.Matched = uint64(len(rows))

	sort.Slice(rows, func(i, j int) bool { return ts(rows[i]) > ts(rows[j]) })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, stats, nil
}

func msSince(t0 time.Time) float64 { return float64(time.Since(t0)) / float64(time.Millisecond) }

func decodeRow(sch *nql.Schema, rec unsafe.Pointer) Row {
	row := make(Row, len(sch.Fields))
	for i, f := range sch.Fields {
		row[i] = FieldValue{Name: f.Name, Value: decodeValue(rec, f)}
	}
	return row
}

func decodeValue(rec unsafe.Pointer, f nql.Field) any {
	switch f.Type {
	case nql.TypeBool:
		return nql.ReadBool(rec, f)
	case nql.TypeIP4:
		a := nql.ReadIP4(rec, f)
		return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
	case nql.TypeI8, nql.TypeI16, nql.TypeI32, nql.TypeI64:
		return nql.ReadInt(rec, f)
	case nql.TypeF64:
		return nql.ReadF64(rec, f)
	case nql.TypeStr:
		return nql.ReadStr(rec, f)
	default:
		return nql.ReadUint(rec, f)
	}
}

func ts(r Row) uint64 {
	for _, fv := range r {
		if fv.Name == "ts" {
			if v, ok := fv.Value.(uint64); ok {
				return v
			}
			return 0
		}
	}
	panic("journal: row has no ts field — every schema in schema.Prelude must declare one")
}
