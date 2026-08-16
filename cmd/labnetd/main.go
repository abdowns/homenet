package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"labnet/internal/api"
	"labnet/internal/ca"
	labnetdns "labnet/internal/dns"
	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/proxy"
	"labnet/internal/schema"
)

const journalCapacity = 1 << 16

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "labnetd:", err)
		os.Exit(1)
	}
}

func run() error {
	zone := flag.String("zone", "lab", "DNS zone labnetd is authoritative for")
	dnsAddr := flag.String("dns-addr", "127.0.0.1:5353",
		"address to serve DNS on (use \":53\" for real use, which needs root/CAP_NET_BIND_SERVICE)")
	apiAddr := flag.String("api-addr", "127.0.0.1:8080", "address to serve the control API on (used by the labnet CLI)")
	proxyAddr := flag.String("proxy-addr", "127.0.0.1:8443",
		"address to serve the HTTPS reverse proxy on (use \":443\" for real use)")
	proxyPlainAddr := flag.String("proxy-plain-addr", "127.0.0.1:8000",
		"address to serve /ca (root cert download) and the https redirect on (use \":80\" for real use)")
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream DNS resolver for names outside zone")
	hostIPFlag := flag.String("host-ip", "", "IP to answer for every name in zone (default: auto-detected)")
	dataDir := flag.String("data-dir", "./data", "directory to persist the local CA (and, later, other state) in")
	routes := flag.String("routes", "", "comma-separated name=host:port backends to proxy as <name>.<zone>, e.g. grafana=127.0.0.1:3000")
	flag.Parse()

	hostIP := net.ParseIP(*hostIPFlag)
	if hostIP == nil {
		var err error
		hostIP, err = detectHostIP()
		if err != nil {
			return fmt.Errorf("auto-detecting --host-ip: %w (pass --host-ip explicitly)", err)
		}
		log.Printf("labnetd: auto-detected --host-ip=%s", hostIP)
	}

	prog, err := nql.Compile(schema.Prelude, "")
	if err != nil {
		return fmt.Errorf("compiling schema prelude (this is a labnetd bug, not a user error): %w", err)
	}
	defer prog.Close()

	dnsRing, err := journal.NewRing(prog, "DnsQuery", journalCapacity)
	if err != nil {
		return fmt.Errorf("creating DNS journal: %w", err)
	}
	defer dnsRing.Close()
	httpRing, err := journal.NewRing(prog, "HttpRequest", journalCapacity)
	if err != nil {
		return fmt.Errorf("creating HTTP journal: %w", err)
	}
	defer httpRing.Close()

	dnsHandler, err := labnetdns.NewHandler(labnetdns.Config{
		Zone: *zone, HostIP: hostIP, Upstream: *upstream, Journal: dnsRing,
	})
	if err != nil {
		return fmt.Errorf("building DNS handler: %w", err)
	}
	dnsServer, err := labnetdns.Listen(*dnsAddr, dnsHandler)
	if err != nil {
		return fmt.Errorf("starting DNS server: %w", err)
	}
	log.Printf("labnetd: DNS serving zone %q on %s -> %s (upstream %s)", *zone, dnsServer.Addr(), hostIP, *upstream)

	authority, err := ca.LoadOrCreate(*dataDir)
	if err != nil {
		return fmt.Errorf("setting up local CA: %w", err)
	}
	registry := proxy.NewRegistry()
	for _, r := range strings.Split(*routes, ",") {
		name, backend, ok := strings.Cut(strings.TrimSpace(r), "=")
		if !ok {
			continue
		}
		registry.Set(name, backend)
		log.Printf("labnetd: routing %s.%s -> %s", name, *zone, backend)
	}
	proxyHandler := &proxy.Proxy{Registry: registry, Journal: httpRing}
	tlsServer := proxy.NewTLSServer(*proxyAddr, proxyHandler, authority)
	plainServer := proxy.NewPlainServer(*proxyPlainAddr, *proxyAddr, authority)

	apiHandler := api.NewServer(*zone, prog, map[string]*journal.Ring{"DnsQuery": dnsRing, "HttpRequest": httpRing}, registry)
	apiServer := &http.Server{Addr: *apiAddr, Handler: apiHandler}

	errc := make(chan error, 4)
	go func() {
		if err := dnsServer.Serve(); err != nil {
			errc <- fmt.Errorf("DNS server: %w", err)
		}
	}()
	go func() {
		log.Printf("labnetd: control API on http://%s", *apiAddr)
		if err := apiServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("control API server: %w", err)
		}
	}()
	go func() {
		log.Printf("labnetd: HTTPS reverse proxy on https://%s", *proxyAddr)
		if err := tlsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("reverse proxy server: %w", err)
		}
	}()
	go func() {
		log.Printf("labnetd: root CA download at http://%s/ca", *proxyPlainAddr)
		if err := plainServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("plain HTTP server: %w", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errc:
		return err
	case s := <-sig:
		log.Printf("labnetd: received %s, shutting down", s)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	apiServer.Shutdown(shutdownCtx)
	tlsServer.Shutdown(shutdownCtx)
	plainServer.Shutdown(shutdownCtx)
	dnsServer.Shutdown()
	return nil
}

// assumes a single nic dev machine
func detectHostIP() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("no non-loopback IPv4 address found")
}
