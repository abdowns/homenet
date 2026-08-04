package nql

/*
#include <nql.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// record array lives in c memory: cgo forbids go pointers reaching c, and
// str fields point into record data. buf owns freeing all of it.
// not safe for concurrent writes, concurrent reads are fine
type Buf struct {
	schema  *Schema
	n       int
	base    unsafe.Pointer
	strings []unsafe.Pointer
}

func NewBuf(schema *Schema, n int) *Buf {
	sz := C.size_t(schema.Size) * C.size_t(n)
	if sz == 0 {
		sz = 1
	}
	base := C.malloc(sz)
	C.memset(base, 0, sz)
	return &Buf{schema: schema, n: n, base: base}
}

// must not be used after, and no kernel call may still be reading it
func (b *Buf) Free() {
	if b.base == nil {
		return
	}
	for _, s := range b.strings {
		C.free(s)
	}
	b.strings = nil
	C.free(b.base)
	b.base = nil
}

func (b *Buf) Len() int { return b.n }

func (b *Buf) Base() unsafe.Pointer { return b.base }

func (b *Buf) Rec(i int) unsafe.Pointer {
	b.checkIndex(i)
	return unsafe.Add(b.base, uintptr(i)*uintptr(b.schema.Size))
}

func (b *Buf) checkIndex(i int) {
	if i < 0 || i >= b.n {
		panic(fmt.Sprintf("nql: record index %d out of range [0,%d)", i, b.n))
	}
}

func (b *Buf) field(name string) Field {
	f, ok := b.schema.Field(name)
	if !ok {
		panic(fmt.Sprintf("nql: schema %q has no field %q", b.schema.Name, name))
	}
	return f
}

func (b *Buf) fieldPtr(i int, f Field) unsafe.Pointer {
	return unsafe.Add(b.Rec(i), uintptr(f.Offset))
}

func (b *Buf) SetUint(i int, field string, v uint64) {
	f := b.field(field)
	p := b.fieldPtr(i, f)
	switch f.Size {
	case 1:
		*(*uint8)(p) = uint8(v)
	case 2:
		*(*uint16)(p) = uint16(v)
	case 4:
		*(*uint32)(p) = uint32(v)
	case 8:
		*(*uint64)(p) = v
	default:
		panic(fmt.Sprintf("nql: field %q has unexpected size %d for SetUint", field, f.Size))
	}
}

func (b *Buf) SetInt(i int, field string, v int64) {
	f := b.field(field)
	p := b.fieldPtr(i, f)
	switch f.Size {
	case 1:
		*(*int8)(p) = int8(v)
	case 2:
		*(*int16)(p) = int16(v)
	case 4:
		*(*int32)(p) = int32(v)
	case 8:
		*(*int64)(p) = v
	default:
		panic(fmt.Sprintf("nql: field %q has unexpected size %d for SetInt", field, f.Size))
	}
}

func (b *Buf) SetF64(i int, field string, v float64) {
	*(*float64)(b.fieldPtr(i, b.field(field))) = v
}

func (b *Buf) SetBool(i int, field string, v bool) {
	var u uint64
	if v {
		u = 1
	}
	b.SetUint(i, field, u)
}

// host order matching nql's ip4 literals: 10.0.0.1 becomes 0x0A000001,
// needed for cidr matching to work
func (b *Buf) SetIP4(i int, field string, a, c1, c2, d byte) {
	v := uint32(a)<<24 | uint32(c1)<<16 | uint32(c2)<<8 | uint32(d)
	b.SetUint(i, field, uint64(v))
}

// bytes are copied into a new c allocation owned by this buf; the go
// string need not outlive the call
func (b *Buf) SetStr(i int, field string, v string) {
	f := b.field(field)
	if f.Type != TypeStr {
		panic(fmt.Sprintf("nql: field %q is not a str field", field))
	}
	var cptr unsafe.Pointer
	var clen C.size_t
	if len(v) > 0 {
		cptr = C.malloc(C.size_t(len(v)))
		C.memcpy(cptr, unsafe.Pointer(unsafe.StringData(v)), C.size_t(len(v)))
		b.strings = append(b.strings, cptr)
		clen = C.size_t(len(v))
	}
	// strref is {ptr, len}, 16 bytes: write both by hand rather than
	// relying on a matching go struct layout
	p := b.fieldPtr(i, f)
	*(*unsafe.Pointer)(p) = cptr
	*(*uint64)(unsafe.Add(p, 8)) = uint64(clen)
}
