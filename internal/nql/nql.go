// needs netdb-lang's libnql built first and pkg_config_path set to its
// build dir, see netdb-lang/README.md
package nql

/*
#cgo pkg-config: nql
#include <nql.h>
#include <stdlib.h>

static int nql_call_pred(bool (*fn)(const void*), const void* rec) {
	return fn(rec) ? 1 : 0;
}
*/
import "C"

import (
	"errors"
	"fmt"
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

func (s *Schema) NewRecord() []byte {
	if s.Size == 0 {
		return nil
	}
	words := make([]uint64, (s.Size+7)/8)
	return unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), s.Size)
}

type Program struct {
	c       *C.nql_program
	schemas []*Schema
	byName  map[string]*Schema
}

func Compile(src string) (*Program, error) {
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))

	var cErr *C.char
	cProg := C.nql_compile(nil, cSrc, &cErr)
	if cProg == nil {
		if cErr == nil {
			return nil, errors.New("nql: compile failed")
		}
		msg := C.GoString(cErr)
		C.nql_free_string(cErr)
		return nil, fmt.Errorf("nql: %s", msg)
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
	return p, nil
}

func (p *Program) Close() {
	if p.c != nil {
		C.nql_free(p.c)
		p.c = nil
	}
}

func (p *Program) Schema(name string) (*Schema, bool) {
	s, ok := p.byName[name]
	return s, ok
}

func (p *Program) Schemas() []*Schema { return p.schemas }

func (p *Program) Match(query string, rec []byte) (bool, error) {
	if len(rec) == 0 {
		return false, errors.New("nql: empty record")
	}
	cName := C.CString(query)
	defer C.free(unsafe.Pointer(cName))
	var ck C.nql_kernels
	if !bool(C.nql_query_kernels(p.c, cName, &ck)) {
		return false, fmt.Errorf("nql: no such query %q", query)
	}
	return C.nql_call_pred(ck.pred, unsafe.Pointer(&rec[0])) != 0, nil
}
