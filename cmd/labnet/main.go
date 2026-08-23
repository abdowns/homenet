package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	// scan for --api before dispatch so it can appear anywhere in args
	args, apiAddr = extractFlag(args, "--api", apiAddr)

	if len(args) == 0 {
		return usageError()
	}

	client := api.NewClient(apiAddr)
	switch args[0] {
	case "q", "query":
		return cmdQuery(client, args[1:])
	case "status":
		return cmdStatus(client)
	case "up":
		return cmdUp(client, args[1:])
	case "down":
		return cmdDown(client, args[1:])
	case "expose":
		return cmdExpose(client, args[1:])
	case "ls":
		return cmdList(client)
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
  labnet up <name> [dir] [--port N]
      build dir's Dockerfile (default: current directory) and run it as
      <name>.<zone>, on labnetd's host (needs Docker there)
  labnet down <name>
      stop and remove a service `+"`up`"+` or `+"`expose`"+` created
  labnet expose <name> <target-url> [--host name.zone]
      proxy an already-running backend (e.g. a local dev server), no
      Docker involved: labnet expose vite http://127.0.0.1:5173
  labnet ls
      list every registered service

LABNET_API (default http://127.0.0.1:8080) sets the labnetd control API
address.`)
	return fmt.Errorf("no command given")
}

func extractFlag(args []string, name, def string) ([]string, string) {
	out := make([]string, 0, len(args))
	val := def
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			val = args[i+1]
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out, val
}

func cmdQuery(client *api.Client, args []string) error {
	args, limitStr := extractFlag(args, "--limit", "0")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		return fmt.Errorf("bad --limit %q: %w", limitStr, err)
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: labnet q <schema> <predicate> [--limit N]")
	}
	schemaName, predicate := args[0], strings.Join(args[1:], " ")

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

func cmdUp(client *api.Client, args []string) error {
	args, portFlag := extractFlag(args, "--port", "")
	if len(args) < 1 {
		return fmt.Errorf("usage: labnet up <name> [dir] [--port N]")
	}
	name := args[0]
	dir := "."
	if len(args) >= 2 {
		dir = args[1]
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving %q: %w", dir, err)
	}

	resp, err := client.Up(api.UpRequest{Name: name, Dir: abs, Port: portFlag})
	if err != nil {
		return err
	}
	fmt.Printf("%s is up at https://%s\n", name, resp.Host)
	return nil
}

func cmdDown(client *api.Client, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: labnet down <name>")
	}
	if err := client.Down(api.DownRequest{Name: args[0]}); err != nil {
		return err
	}
	fmt.Printf("%s is down\n", args[0])
	return nil
}

func cmdExpose(client *api.Client, args []string) error {
	args, host := extractFlag(args, "--host", "")
	if len(args) != 2 {
		return fmt.Errorf("usage: labnet expose <name> <target-url> [--host name.zone]")
	}
	name, target := args[0], args[1]

	svc, err := client.Expose(api.ExposeRequest{Name: name, Host: host, Target: target})
	if err != nil {
		return err
	}
	fmt.Printf("%s -> https://%s -> %s\n", svc.Name, svc.Host, svc.Target)
	return nil
}

func cmdList(client *api.Client) error {
	services, err := client.ListServices()
	if err != nil {
		return err
	}
	if len(services) == 0 {
		fmt.Println("no services registered")
		return nil
	}
	for _, svc := range services {
		fmt.Printf("%-20s https://%-24s -> %s\n", svc.Name, svc.Host, svc.Target)
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
