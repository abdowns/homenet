package nql

import "unsafe"

// ip4 comes back zero extended, host order: first octet is the most
// significant byte, same as setip4 writes
func ReadUint(rec unsafe.Pointer, f Field) uint64 {
	p := unsafe.Add(rec, uintptr(f.Offset))
	switch f.Size {
	case 1:
		return uint64(*(*uint8)(p))
	case 2:
		return uint64(*(*uint16)(p))
	case 4:
		return uint64(*(*uint32)(p))
	default:
		return *(*uint64)(p)
	}
}

func ReadInt(rec unsafe.Pointer, f Field) int64 {
	p := unsafe.Add(rec, uintptr(f.Offset))
	switch f.Size {
	case 1:
		return int64(*(*int8)(p))
	case 2:
		return int64(*(*int16)(p))
	case 4:
		return int64(*(*int32)(p))
	default:
		return *(*int64)(p)
	}
}

func ReadF64(rec unsafe.Pointer, f Field) float64 {
	return *(*float64)(unsafe.Add(rec, uintptr(f.Offset)))
}

func ReadBool(rec unsafe.Pointer, f Field) bool {
	return ReadUint(rec, f) != 0
}

func ReadIP4(rec unsafe.Pointer, f Field) [4]byte {
	v := uint32(ReadUint(rec, f))
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// copies out of c memory into a go string, independent of the record's
// lifetime after this call
func ReadStr(rec unsafe.Pointer, f Field) string {
	p := unsafe.Add(rec, uintptr(f.Offset))
	ptr := *(*unsafe.Pointer)(p)
	length := *(*uint64)(unsafe.Add(p, 8))
	if ptr == nil || length == 0 {
		return ""
	}
	return unsafe.String((*byte)(ptr), int(length))
}
