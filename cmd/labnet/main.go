package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"labnet/internal/api"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "labnet:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	apiAddr := os.Getenv("LABNET_API")
	if apiAddr == "" {
		apiAddr = "http://127.0.0.1:8080"
	}
	if len(args) >= 2 && args[0] == "--api" {
		apiAddr = args[1]
		args = args[2:]
	}

	if len(args) == 0 {
		return usageError()
	}

	client := api.NewClient(apiAddr)
	switch args[0] {
	case "q", "query":
		return cmdQuery(client, args[1:])
	case "status":
		return cmdStatus(client)
	default:
		return usageError()
	}
}

func usageError() error {
	fmt.Fprintln(os.Stderr, `usage:
  labnet [--api http://host:port] q <schema> <predicate> [--limit N]
      run an ad-hoc query against a journal, e.g.:
      labnet q DnsQuery "blocked"
      labnet q DnsQuery "qtype == 1 and not upstream" --limit 5
  labnet [--api http://host:port] status
      show labnetd's zone, uptime, journal sizes and known schemas

LABNET_API (default http://127.0.0.1:8080) sets the labnetd control API
address.`)
	return fmt.Errorf("no command given")
}

func cmdQuery(client *api.Client, args []string) error {
	limit := 0
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--limit" && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("bad --limit %q: %w", args[i+1], err)
			}
			limit = n
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) < 2 {
		return fmt.Errorf("usage: labnet q <schema> <predicate> [--limit N]")
	}
	schemaName, predicate := rest[0], strings.Join(rest[1:], " ")

	resp, err := client.Query(api.QueryRequest{Schema: schemaName, Predicate: predicate, Limit: limit})
	if err != nil {
		return err
	}
	fmt.Printf("compiled in %.2fms, scanned %d record(s) in %.3fms, %d matched\n",
		resp.CompileMS, resp.Scanned, resp.ScanMS, resp.Matched)
	for _, row := range resp.Rows {
		var parts []string
		for _, fv := range row {
			parts = append(parts, fmt.Sprintf("%s=%v", fv.Name, fv.Value))
		}
		fmt.Println(strings.Join(parts, "  "))
	}
	return nil
}

func cmdStatus(client *api.Client) error {
	st, err := client.Status()
	if err != nil {
		return err
	}
	fmt.Printf("zone:   %s\n", st.Zone)
	fmt.Printf("uptime: %s\n", st.Uptime)
	fmt.Println("journals:")
	for name, counts := range st.Ringlen {
		fmt.Printf("  %-12s %6d held / %8d lifetime\n", name, counts.Len, counts.Total)
	}
	fmt.Println("schemas:")
	for name := range st.Schemas {
		fmt.Printf("  %s\n", name)
	}
	return nil
}
