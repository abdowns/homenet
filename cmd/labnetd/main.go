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
	"path/filepath"
	"syscall"
	"time"

	"labnet/internal/api"
	"labnet/internal/auth"
	"labnet/internal/ca"
	labnetdns "labnet/internal/dns"
	"labnet/internal/docker"
	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/policy"
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
	policyFile := flag.String("policy-file", "./policies/policy.nql",
		"NQL policy file, hot-reloaded on save (see internal/policy); missing is treated as an empty, no-op policy")
	dockerSocket := flag.String("docker-socket", "/var/run/docker.sock", "Docker Engine API socket path")
	dockerNetwork := flag.String("docker-network", "labnet", "Docker network `labnet up` attaches services to")
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
	authRing, err := journal.NewRing(prog, "AuthEvent", journalCapacity)
	if err != nil {
		return fmt.Errorf("creating auth journal: %w", err)
	}
	defer authRing.Close()

	authStore, err := auth.Open(filepath.Join(*dataDir, "auth.db"))
	if err != nil {
		return fmt.Errorf("opening auth database: %w", err)
	}
	defer authStore.Close()
	bootstrapCode, err := authStore.EnsureBootstrapCode(context.Background(), 24*time.Hour)
	if err != nil {
		return fmt.Errorf("preparing pairing code: %w", err)
	}
	if bootstrapCode != "" {
		log.Printf("labnetd: no devices paired yet — pairing code %s (valid 24h)", bootstrapCode)
		log.Printf("labnetd: pair a device at http://%s%s%s or https://<any *.lab name>%s%s",
			hostIP, portSuffix(*proxyPlainAddr), auth.PairPath, portSuffix(*proxyAddr), auth.PairPath)
	}
	gate := &auth.Gate{Store: authStore, CookieDomain: "." + *zone}

	policyMgr, err := policy.NewManager(*policyFile)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	alertLog := policy.NewAlertLog(200)
	raiseAlerts := func(schemaName string, names []string, summary string) {
		for _, rule := range names {
			log.Printf("labnetd: ALERT %s (%s): %s", rule, schemaName, summary)
			alertLog.Add(policy.Alert{TS: uint64(time.Now().UnixMilli()), Schema: schemaName, Rule: rule, Summary: summary})
		}
	}

	pairHandler := auth.NewPairHandler(authStore, *zone, func(e auth.AuthEvent) {
		var client [4]byte
		if v4 := e.Client.To4(); v4 != nil {
			copy(client[:], v4)
		}
		rec := schema.AuthEvent{TS: e.TS, Client: client, Device: e.Device, Kind: e.Kind, OK: e.OK}
		authRing.Append(func(buf *nql.Buf, i int) { schema.PackAuthEvent(buf, i, rec) })
		raiseAlerts("AuthEvent", policyMgr.Current().AlertsAuth(rec), fmt.Sprintf("device=%s kind=%s ok=%v", rec.Device, rec.Kind, rec.OK))
	})

	dnsHandler, err := labnetdns.NewHandler(labnetdns.Config{
		Zone: *zone, HostIP: hostIP, Upstream: *upstream, Journal: dnsRing,
		Policy: func(q schema.DnsQuery) bool { blocked, _ := policyMgr.Current().BlockDNS(q); return blocked },
		OnComplete: func(q schema.DnsQuery) {
			raiseAlerts("DnsQuery", policyMgr.Current().AlertsDNS(q), fmt.Sprintf("name=%s blocked=%v", q.Name, q.Blocked))
		},
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
	proxyHandler := &proxy.Proxy{
		Registry: registry, Journal: httpRing,
		Authenticate: gate.Authenticate, PairPath: auth.PairPath, PairHandler: pairHandler,
		Policy: func(r schema.HttpRequest) bool { denied, _ := policyMgr.Current().DenyHTTP(r); return denied },
		Public: func(r schema.HttpRequest) bool { pub, _ := policyMgr.Current().IsPublicHTTP(r); return pub },
		OnComplete: func(r schema.HttpRequest) {
			raiseAlerts("HttpRequest", policyMgr.Current().AlertsHTTP(r), fmt.Sprintf("%s %s -> %d", r.Method, r.Path, r.Status))
		},
	}
	tlsServer := proxy.NewTLSServer(*proxyAddr, proxyHandler, authority)
	plainServer := proxy.NewPlainServer(*proxyPlainAddr, *proxyAddr, authority, auth.PairPath, pairHandler)

	sdk := docker.NewSDKClient(*dockerSocket)
	probeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, err = sdk.ListContainers(probeCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("connecting to Docker at %s: %w", *dockerSocket, err)
	}
	discovery := docker.NewDiscovery(sdk, registry, 5*time.Second)
	log.Printf("labnetd: Docker discovery active on network %q", *dockerNetwork)

	apiHandler := api.NewServer(*zone, prog, map[string]*journal.Ring{"DnsQuery": dnsRing, "HttpRequest": httpRing, "AuthEvent": authRing},
		api.Services{Registry: registry, Docker: sdk, Discovery: discovery, DockerNetwork: *dockerNetwork},
		api.PolicyDeps{Manager: policyMgr, Alerts: alertLog},
		api.AuthDeps{Store: authStore},
	)
	apiServer := &http.Server{Addr: *apiAddr, Handler: apiHandler}

	ctx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	go discovery.Run(ctx)
	go func() {
		if err := policyMgr.Watch(ctx.Done()); err != nil {
			log.Printf("labnetd: policy watcher stopped: %v", err)
		}
	}()
	log.Printf("labnetd: policy loaded from %s (%s)", *policyFile, ruleSummary(policyMgr.Current().RuleNames()))

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

func portSuffix(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ""
	}
	return ":" + port
}

func ruleSummary(rules map[string][]string) string {
	total := 0
	for _, names := range rules {
		total += len(names)
	}
	if total == 0 {
		return "no rules — every request/query is allowed"
	}
	return fmt.Sprintf("%d deny_, %d allow_, %d public_, %d block_, %d alert_ rule(s)",
		len(rules["deny_"]), len(rules["allow_"]), len(rules["public_"]), len(rules["block_"]), len(rules["alert_"]))
}
