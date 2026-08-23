package proxy

import (
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

type Service struct {
	Name   string
	Host   string
	Target *url.URL

	rp *httputil.ReverseProxy
}

type Registry struct {
	mu     sync.RWMutex
	byHost map[string]*Service
}

func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func NewRegistry() *Registry {
	return &Registry{byHost: map[string]*Service{}}
}

func (r *Registry) Register(name, host string, target *url.URL) *Service {
	svc := &Service{
		Name:   name,
		Host:   normalizeHost(host),
		Target: target,
		rp:     httputil.NewSingleHostReverseProxy(target),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byHost[svc.Host] = svc
	return svc
}

func (r *Registry) Deregister(host string) bool {
	host = normalizeHost(host)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byHost[host]; !ok {
		return false
	}
	delete(r.byHost, host)
	return true
}

// at most one match: Register overwrites any existing entry for a host
func (r *Registry) DeregisterByName(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for host, svc := range r.byHost {
		if svc.Name == name {
			delete(r.byHost, host)
			return true
		}
	}
	return false
}

// host may include a port; callers should strip it first via StripPort
func (r *Registry) Lookup(host string) (*Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	svc, ok := r.byHost[normalizeHost(host)]
	return svc, ok
}

func (r *Registry) List() []*Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Service, 0, len(r.byHost))
	for _, svc := range r.byHost {
		out = append(out, svc)
	}
	return out
}

// a bracketless IPv6 host can't appear in a valid Host header, so a plain
// LastIndex is safe here
func StripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i != -1 {
		return host[:i]
	}
	return host
}
