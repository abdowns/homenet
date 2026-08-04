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

// record array lives in c memory: cgo forbids go pointers reaching c.
// buf owns freeing it.
// not safe for concurrent writes, concurrent reads are fine
type Buf struct {
	schema *Schema
	n      int
	base   unsafe.Pointer
}

func NewBuf(schema *Schema, n int) *Buf {
	sz := C.size_t(schema.Size) * C.size_t(n)
	base := C.malloc(sz)
	C.memset(base, 0, sz)
	return &Buf{schema: schema, n: n, base: base}
}

// must not be used after, and no kernel call may still be reading it
func (b *Buf) Free() {
	if b.base == nil {
		return
	}
	C.free(b.base)
	b.base = nil
}

func (b *Buf) Len() int { return b.n }

func (b *Buf) Base() unsafe.Pointer { return b.base }

func (b *Buf) Rec(i int) unsafe.Pointer {
	if i < 0 || i >= b.n {
		panic(fmt.Sprintf("nql: record index %d out of range [0,%d)", i, b.n))
	}
	return unsafe.Add(b.base, uintptr(i)*uintptr(b.schema.Size))
}

func (b *Buf) SetUint(i int, field string, v uint64) {
	f, ok := b.schema.Field(field)
	if !ok {
		panic(fmt.Sprintf("nql: schema %q has no field %q", b.schema.Name, field))
	}
	p := unsafe.Add(b.Rec(i), uintptr(f.Offset))
	switch f.Size {
	case 1:
		*(*uint8)(p) = uint8(v)
	case 2:
		*(*uint16)(p) = uint16(v)
	case 4:
		*(*uint32)(p) = uint32(v)
	default:
		*(*uint64)(p) = v
	}
}

func (b *Buf) SetBool(i int, field string, v bool) {
	if v {
		b.SetUint(i, field, 1)
	} else {
		b.SetUint(i, field, 0)
	}
}
