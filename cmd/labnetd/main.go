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
	"syscall"
	"time"

	"labnet/internal/api"
	labnetdns "labnet/internal/dns"
	"labnet/internal/journal"
	"labnet/internal/nql"
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
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream DNS resolver for names outside zone")
	hostIPFlag := flag.String("host-ip", "", "IP to answer for every name in zone (default: auto-detected)")
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

	apiHandler := api.NewServer(*zone, prog, map[string]*journal.Ring{"DnsQuery": dnsRing})
	apiServer := &http.Server{Addr: *apiAddr, Handler: apiHandler}

	errc := make(chan error, 2)
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
