package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	labnetdns "labnet/internal/dns"
)

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
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream DNS resolver for names outside zone")
	hostIPFlag := flag.String("host-ip", "", "IP to answer for every name in zone (default: auto-detected)")
	flag.Parse()

	hostIP := net.ParseIP(*hostIPFlag)
	if hostIP == nil {
		var err error
		hostIP, err = detectHostIP()
		if err != nil {
			return fmt.Errorf("auto-detecting --host-ip: %w", err)
		}
		log.Printf("labnetd: auto-detected --host-ip=%s", hostIP)
	}

	handler := labnetdns.NewHandler(*zone, hostIP, *upstream)
	dnsServer, err := labnetdns.Listen(*dnsAddr, handler)
	if err != nil {
		return fmt.Errorf("starting DNS server: %w", err)
	}
	log.Printf("labnetd: DNS serving zone %q on %s -> %s (upstream %s)", *zone, dnsServer.Addr(), hostIP, *upstream)

	errc := make(chan error, 1)
	go func() {
		errc <- dnsServer.Serve()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errc:
		return fmt.Errorf("DNS server: %w", err)
	case s := <-sig:
		log.Printf("labnetd: received %s, shutting down", s)
	}

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
