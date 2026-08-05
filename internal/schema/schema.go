package schema

import (
	"net"
	"time"
)

// field order must match the structs below, keep in sync
const Prelude = `
schema DnsQuery {
  ts:       u64
  client:   ip4
  name:     str
  qtype:    u16
  rcode:    u8
  blocked:  bool
  upstream: bool
  ms:       f64
}

schema HttpRequest {
  ts:      u64
  client:  ip4
  service: str
  host:    str
  method:  str
  path:    str
  status:  u16
  bytes:   u32
  ms:      f64
}
`

type DnsQuery struct {
	TS       uint64
	Client   [4]byte
	Name     string
	QType    uint16
	RCode    uint8
	Blocked  bool
	Upstream bool
	MS       float64
}

// status/bytes/ms are zero until the response is known, filled in before journaling
type HttpRequest struct {
	TS      uint64
	Client  [4]byte
	Service string
	Host    string
	Method  string
	Path    string
	Status  uint16
	Bytes   uint32
	MS      float64
}

func PackIP4(ip net.IP) [4]byte {
	var out [4]byte
	copy(out[:], ip.To4())
	return out
}

func PackTS(t time.Time) uint64 {
	return uint64(t.UnixNano())
}

func PackMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
