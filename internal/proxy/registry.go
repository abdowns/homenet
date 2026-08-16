package proxy

import (
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

type Service struct {
	Host   string
	Target *url.URL

	rp *httputil.ReverseProxy
}

type Registry struct {
	mu     sync.RWMutex
	byHost map[string]*Service
}

func NewRegistry() *Registry {
	return &Registry{byHost: map[string]*Service{}}
}

func (r *Registry) Register(host string, target *url.URL) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byHost[strings.ToLower(host)] = &Service{
		Host:   host,
		Target: target,
		rp:     httputil.NewSingleHostReverseProxy(target),
	}
}

func (r *Registry) Lookup(host string) (*Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	svc, ok := r.byHost[strings.ToLower(host)]
	return svc, ok
}

func StripPort(host string) string {
	if i := strings.Index(host, ":"); i != -1 {
		return host[:i]
	}
	return host
}
