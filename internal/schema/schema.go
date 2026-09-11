package schema

// field order must match the structs below, keep in sync
const Prelude = `
schema DnsQuery {
  ts:       u64
  client:   ip4
  device:   str
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
  device:  str
  user:    str
  service: str
  host:    str
  method:  str
  path:    str
  agent:   str
  status:  u16
  bytes:   u32
  ms:      f64
  authed:  bool
}

schema AuthEvent {
  ts:     u64
  client: ip4
  device: str
  user:   str
  kind:   str
  ok:     bool
}
`

type DnsQuery struct {
	TS       uint64
	Client   [4]byte
	Device   string
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
	Device  string
	User    string
	Service string
	Host    string
	Method  string
	Path    string
	Agent   string
	Status  uint16
	Bytes   uint32
	MS      float64
	Authed  bool
}

type AuthEvent struct {
	TS     uint64
	Client [4]byte
	Device string
	User   string
	Kind   string // password, device pair, token
	OK     bool
}
