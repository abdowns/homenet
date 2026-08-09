// needs netdb-lang's libnql built first and pkg_config_path set to its
// build dir, see netdb-lang/README.md
package nql

/*
#cgo pkg-config: nql
#include <nql.h>
#include <stdlib.h>

// cgo cant call a c function pointer directly from go, so these
// trampolines do it; each mirrors one nql_kernels field's c signature
static int nql_call_pred(bool (*fn)(const void*), const void* rec) {
	return fn(rec) ? 1 : 0;
}
static uint64_t nql_call_count(uint64_t (*fn)(const void*, uint64_t), const void* base, uint64_t n) {
	return fn(base, n);
}
static uint64_t nql_call_collect(uint64_t (*fn)(const void*, uint64_t, uint64_t*, uint64_t),
                                 const void* base, uint64_t n, uint64_t* out, uint64_t cap) {
	return fn(base, n, out, cap);
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

type Type int32

const (
	TypeInvalid Type = Type(C.NQL_INVALID)
	TypeBool    Type = Type(C.NQL_BOOL)
	TypeU8      Type = Type(C.NQL_U8)
	TypeU16     Type = Type(C.NQL_U16)
	TypeU32     Type = Type(C.NQL_U32)
	TypeU64     Type = Type(C.NQL_U64)
	TypeI8      Type = Type(C.NQL_I8)
	TypeI16     Type = Type(C.NQL_I16)
	TypeI32     Type = Type(C.NQL_I32)
	TypeI64     Type = Type(C.NQL_I64)
	TypeF64     Type = Type(C.NQL_F64)
	TypeStr     Type = Type(C.NQL_STR)
	TypeIP4     Type = Type(C.NQL_IP4)
)

func (t Type) String() string {
	switch t {
	case TypeBool:
		return "bool"
	case TypeU8:
		return "u8"
	case TypeU16:
		return "u16"
	case TypeU32:
		return "u32"
	case TypeU64:
		return "u64"
	case TypeI8:
		return "i8"
	case TypeI16:
		return "i16"
	case TypeI32:
		return "i32"
	case TypeI64:
		return "i64"
	case TypeF64:
		return "f64"
	case TypeStr:
		return "str"
	case TypeIP4:
		return "ip4"
	default:
		return "invalid"
	}
}

type Field struct {
	Name   string
	Type   Type
	Offset uint32
	Size   uint32
	Align  uint32
}

type Schema struct {
	Name   string
	Size   uint32
	Align  uint32
	Fields []Field
}

func (s *Schema) Field(name string) (Field, bool) {
	for _, f := range s.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// zero value: pred/count must not be called, hascollect() is false
type Kernels struct {
	ck C.nql_kernels
}

func (k Kernels) Pred(rec unsafe.Pointer) bool {
	return C.nql_call_pred(k.ck.pred, rec) != 0
}

func (k Kernels) Count(base unsafe.Pointer, n uint64) uint64 {
	return uint64(C.nql_call_count(k.ck.count, base, C.uint64_t(n)))
}

// false for a query with no where clause: every record matches, caller
// should just iterate instead
func (k Kernels) HasCollect() bool {
	return k.ck.collect != nil
}

// a returned count equal to len(outIdx) means there may be more matches
// than fit
func (k Kernels) Collect(base unsafe.Pointer, n uint64, outIdx []uint64) uint64 {
	if len(outIdx) == 0 {
		return 0
	}
	return uint64(C.nql_call_collect(k.ck.collect, base, C.uint64_t(n),
		(*C.uint64_t)(unsafe.Pointer(&outIdx[0])), C.uint64_t(len(outIdx))))
}

// safe for concurrent use, kernel calls are pure reads; must not be used
// after Close
type Program struct {
	c       *C.nql_program
	schemas []*Schema
	byName  map[string]*Schema
}

// a syntax/type error in usersrc comes back as *compileerror with a
// line:col relative to usersrc alone, not prelude+usersrc
func Compile(prelude, userSrc string) (*Program, error) {
	cPrelude := C.CString(prelude)
	defer C.free(unsafe.Pointer(cPrelude))
	cUser := C.CString(userSrc)
	defer C.free(unsafe.Pointer(cUser))

	var cErr *C.char
	cProg := C.nql_compile(cPrelude, cUser, &cErr)
	if cProg == nil {
		msg := "nql_compile failed with no error message"
		if cErr != nil {
			msg = C.GoString(cErr)
			C.nql_free_string(cErr)
		}
		return nil, &CompileError{Message: msg}
	}

	p := &Program{c: cProg, byName: map[string]*Schema{}}
	n := int(C.nql_schema_count(cProg))
	for i := 0; i < n; i++ {
		cs := C.nql_schema_at(cProg, C.size_t(i))
		s := &Schema{
			Name:  C.GoString(cs.name),
			Size:  uint32(cs.size),
			Align: uint32(cs.align),
		}
		nf := int(cs.field_count)
		s.Fields = make([]Field, nf)
		for j := 0; j < nf; j++ {
			cf := C.nql_field_at(cs, C.size_t(j))
			s.Fields[j] = Field{
				Name:   C.GoString(cf.name),
				Type:   Type(cf.ty),
				Offset: uint32(cf.offset),
				Size:   uint32(cf.size),
				Align:  uint32(cf.align),
			}
		}
		p.schemas = append(p.schemas, s)
		p.byName[s.Name] = s
	}

	runtime.SetFinalizer(p, (*Program).Close)
	return p, nil
}

type CompileError struct{ Message string }

func (e *CompileError) Error() string { return e.Message }

func (p *Program) Close() {
	if p.c != nil {
		runtime.SetFinalizer(p, nil)
		C.nql_free(p.c)
		p.c = nil
	}
}

func (p *Program) Schema(name string) (*Schema, bool) {
	s, ok := p.byName[name]
	return s, ok
}

func (p *Program) Schemas() []*Schema { return p.schemas }

func (p *Program) QueryKernels(name string) (Kernels, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	var ck C.nql_kernels
	if !bool(C.nql_query_kernels(p.c, cName, &ck)) {
		return Kernels{}, fmt.Errorf("nql: no such query %q", name)
	}
	return Kernels{ck: ck}, nil
}
