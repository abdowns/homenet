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

// pairHandler is mounted outside TLS too, so a brand new device can pair
// before it has any reason to trust our certificate
func NewPlainServer(addr, httpsAddr string, authority *ca.CA, pairPath string, pairHandler http.Handler) *http.Server {
	suffix := httpsPortSuffix(httpsAddr)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ca", CAHandler(authority))
	if pairPath != "" && pairHandler != nil {
		mux.Handle(pairPath, pairHandler)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + StripPort(r.Host) + suffix + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
	return &http.Server{Addr: addr, Handler: mux}
}
