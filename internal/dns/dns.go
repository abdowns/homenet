package dns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/schema"
)

type PolicyFunc func(q schema.DnsQuery) (blocked bool)

type Config struct {
	Zone       string
	HostIP     net.IP
	Upstream   string
	Journal    *journal.Ring
	Policy     PolicyFunc
	OnComplete func(q schema.DnsQuery)
}

type Handler struct {
	zone       string
	hostIP     net.IP
	upstream   string
	journal    *journal.Ring
	policy     PolicyFunc
	onComplete func(q schema.DnsQuery)
	client     *dns.Client
}

func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Zone == "" {
		return nil, fmt.Errorf("dns: Config.Zone is required")
	}
	if cfg.Upstream == "" {
		return nil, fmt.Errorf("dns: Config.Upstream is required")
	}
	return &Handler{
		zone:       dns.Fqdn(cfg.Zone),
		hostIP:     cfg.HostIP,
		upstream:   cfg.Upstream,
		journal:    cfg.Journal,
		policy:     cfg.Policy,
		onComplete: cfg.OnComplete,
		client:     &dns.Client{Timeout: 3 * time.Second},
	}, nil
}

func clientIP4(w dns.ResponseWriter) [4]byte {
	a, ok := w.RemoteAddr().(*net.UDPAddr)
	if !ok || a.IP == nil {
		return [4]byte{}
	}
	v4 := a.IP.To4()
	if v4 == nil {
		return [4]byte{} // ipv6 clients not represented, ip4 only for v1
	}
	return [4]byte{v4[0], v4[1], v4[2], v4[3]}
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	t0 := time.Now()
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.Compress = true

	rec := schema.DnsQuery{
		TS:     uint64(t0.UnixMilli()),
		Client: clientIP4(w),
	}

	if len(r.Question) != 1 {
		reply.Rcode = dns.RcodeFormatError
		w.WriteMsg(reply)
		return
	}
	q := r.Question[0]
	rec.Name = q.Name
	rec.QType = q.Qtype

	if h.policy != nil && h.policy(rec) {
		// checked before zone split: block rules target ad/tracker domains,
		// almost never under our own zone
		rec.Blocked = true
		reply.Rcode = dns.RcodeNameError
	} else if dns.IsSubDomain(h.zone, q.Name) {
		if q.Qtype == dns.TypeA && h.hostIP != nil {
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, h.hostIP))
			if err == nil {
				reply.Answer = append(reply.Answer, rr)
			}
		}
	} else {
		rec.Upstream = true
		resp, _, err := h.client.Exchange(r, h.upstream)
		if err == nil && resp != nil {
			resp.Id = r.Id
			reply = resp
		} else {
			reply.Rcode = dns.RcodeServerFailure
		}
	}

	rec.RCode = uint8(reply.Rcode)
	rec.MS = float64(time.Since(t0)) / float64(time.Millisecond)
	if h.onComplete != nil {
		h.onComplete(rec)
	}
	if h.journal != nil {
		h.journal.Append(func(buf *nql.Buf, i int) { schema.PackDnsQuery(buf, i, rec) })
	}

	w.WriteMsg(reply)
}
