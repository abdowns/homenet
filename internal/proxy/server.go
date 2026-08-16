package proxy

import (
	"crypto/tls"
	"net"
	"net/http"

	"labnet/internal/ca"
)

func httpsPortSuffix(httpsAddr string) string {
	_, port, err := net.SplitHostPort(httpsAddr)
	if err != nil || port == "" || port == "443" {
		return ""
	}
	return ":" + port
}

func NewTLSServer(addr string, p *Proxy, authority *ca.CA) *http.Server {
	return &http.Server{
		Addr:      addr,
		Handler:   p,
		TLSConfig: &tls.Config{GetCertificate: authority.GetCertificate},
	}
}

// plain http, not https: a device can't trust our root before fetching it
func CAHandler(authority *ca.CA) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="labnet-root-ca.pem"`)
		w.Write(authority.RootPEM())
	}
}

func NewPlainServer(addr, httpsAddr string, authority *ca.CA) *http.Server {
	suffix := httpsPortSuffix(httpsAddr)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ca", CAHandler(authority))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := StripPort(r.Host)
		http.Redirect(w, r, "https://"+host+suffix+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
	return &http.Server{Addr: addr, Handler: mux}
}
