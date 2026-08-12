package dns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type Handler struct {
	zone     string
	hostIP   net.IP
	upstream string
	client   *dns.Client
}

func NewHandler(zone string, hostIP net.IP, upstream string) *Handler {
	return &Handler{
		zone:     dns.Fqdn(zone),
		hostIP:   hostIP,
		upstream: upstream,
		client:   &dns.Client{Timeout: 3 * time.Second},
	}
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.Compress = true

	if len(r.Question) != 1 {
		reply.Rcode = dns.RcodeFormatError
		w.WriteMsg(reply)
		return
	}
	q := r.Question[0]

	if dns.IsSubDomain(h.zone, q.Name) {
		if q.Qtype == dns.TypeA && h.hostIP != nil {
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, h.hostIP))
			if err == nil {
				reply.Answer = append(reply.Answer, rr)
			}
		}
		w.WriteMsg(reply)
		return
	}

	resp, _, err := h.client.Exchange(r, h.upstream)
	if err != nil || resp == nil {
		reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(reply)
		return
	}
	resp.Id = r.Id
	w.WriteMsg(resp)
}
