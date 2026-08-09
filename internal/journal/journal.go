package journal

import (
	"fmt"
	"sort"
	"sync"
	"unsafe"

	"labnet/internal/nql"
	"labnet/internal/schema"
)

const (
	segCap  = 4096
	maxSegs = 16
)

type Row map[string]any

type segment struct {
	buf   *nql.Buf
	count int
}

// safe for concurrent use
type Ring struct {
	mu         sync.RWMutex
	schemaName string
	sch        *nql.Schema
	segs       []*segment // oldest first
	total      uint64
}

func NewRing(prog *nql.Program, schemaName string) (*Ring, error) {
	sch, ok := prog.Schema(schemaName)
	if !ok {
		return nil, fmt.Errorf("journal: no such schema %q", schemaName)
	}
	return &Ring{schemaName: schemaName, sch: sch}, nil
}

func (r *Ring) Append(fill func(buf *nql.Buf, i int)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.segs) == 0 || r.segs[len(r.segs)-1].count >= segCap {
		r.segs = append(r.segs, &segment{buf: nql.NewBuf(r.sch, segCap)})
		if len(r.segs) > maxSegs {
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

func (r *Ring) Query(predicate string, limit int) ([]Row, error) {
	src := fmt.Sprintf("filter __adhoc(r: %s) {\n%s\n}\n", r.schemaName, predicate)
	prog, err := nql.Compile(schema.Prelude, src)
	if err != nil {
		return nil, err
	}
	defer prog.Close()

	k, ok := prog.FilterKernels("__adhoc")
	if !ok {
		return nil, fmt.Errorf("journal: internal error: __adhoc filter missing after compile")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	var rows []Row
	for _, s := range r.segs {
		if s.count == 0 {
			continue
		}
		idx := make([]uint64, s.count)
		got := k.Collect(s.buf.Base(), uint64(s.count), idx)
		for _, i := range idx[:got] {
			rows = append(rows, decodeRow(r.sch, s.buf.Rec(int(i))))
		}
	}

	sort.Slice(rows, func(i, j int) bool { return ts(rows[i]) > ts(rows[j]) })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func decodeRow(sch *nql.Schema, rec unsafe.Pointer) Row {
	row := make(Row, len(sch.Fields))
	for _, f := range sch.Fields {
		row[f.Name] = decodeValue(rec, f)
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
	v, _ := r["ts"].(uint64)
	return v
}
