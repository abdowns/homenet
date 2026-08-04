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

type Field struct {
	Name   string
	Type   int32
	Offset uint32
	Size   uint32
}

type Schema struct {
	Name   string
	Size   uint32
	Fields []Field
}

func (s *Schema) NewRecord() []byte {
	return make([]byte, s.Size)
}

type Program struct {
	c       *C.nql_program
	schemas map[string]*Schema
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

	p := &Program{c: cProg, schemas: map[string]*Schema{}}
	n := int(C.nql_schema_count(cProg))
	for i := 0; i < n; i++ {
		cs := C.nql_schema_at(cProg, C.size_t(i))
		s := &Schema{Name: C.GoString(cs.name), Size: uint32(cs.size)}
		for j := 0; j < int(cs.field_count); j++ {
			cf := C.nql_field_at(cs, C.size_t(j))
			s.Fields = append(s.Fields, Field{
				Name:   C.GoString(cf.name),
				Type:   int32(cf.ty),
				Offset: uint32(cf.offset),
				Size:   uint32(cf.size),
			})
		}
		p.schemas[s.Name] = s
	}
	return p, nil
}

func (p *Program) Close() {
	if p.c != nil {
		C.nql_free(p.c)
		p.c = nil
	}
}

func (p *Program) Schema(name string) *Schema {
	return p.schemas[name]
}

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
