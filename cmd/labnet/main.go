package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"labnet/internal/api"
	"labnet/internal/auth"
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

	if args[0] == "pair" {
		return cmdPair(args[1:])
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
	case "policy":
		return cmdPolicy(client, args[1:])
	case "alerts":
		return cmdAlerts(client)
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
  labnet pair <code> [--name mydevice] [--pair-url http://host:port]
      redeem a pairing code (shown by labnetd on first run, or minted by
      an already-paired device) and print this device's bearer token
  labnet policy check <file>
      compile a candidate policy.nql without applying it
  labnet policy test <file>
      show what a candidate policy.nql would deny/block against the
      *current* journal, without applying it
  labnet policy apply <file>
      compile, persist, and hot-swap in a candidate policy.nql
  labnet policy status
      show the currently active policy's rules by category
  labnet alerts
      show recent alert_* rule matches

LABNET_API (default http://127.0.0.1:8080) sets the labnetd control API
address (used by everything except pair). LABNET_PAIR_URL (default
http://127.0.0.1:8000) sets where pair looks for the pairing endpoint.`)
	return fmt.Errorf("no command given")
}

func extractFlag(args []string, name, def string) ([]string, string) {
	out := make([]string, 0, len(args))
	val := def
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == name && i+1 < len(args) {
			val = args[i+1]
			i++
			continue
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			val = v
			continue
		}
		out = append(out, a)
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

func cmdPair(args []string) error {
	pairURL := os.Getenv("LABNET_PAIR_URL")
	if pairURL == "" {
		pairURL = "http://127.0.0.1:8000"
	}
	args, pairURL = extractFlag(args, "--pair-url", pairURL)
	args, name := extractFlag(args, "--name", "")
	if len(args) != 1 {
		return fmt.Errorf("usage: labnet pair <code> [--name mydevice] [--pair-url http://host:port]")
	}
	code := args[0]

	resp, err := http.PostForm(pairURL+auth.PairPath, url.Values{"code": {code}, "name": {name}})
	if err != nil {
		return fmt.Errorf("labnetd unreachable at %s: %w", pairURL, err)
	}
	defer resp.Body.Close()

	var token string
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			token = c.Value
		}
	}
	if resp.StatusCode != http.StatusOK || token == "" {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("pairing failed (status %s) — bad or expired code?", resp.Status)
	}

	fmt.Println("paired! this device's bearer token (keep it secret):")
	fmt.Println(token)
	fmt.Println()
	fmt.Println(`use it as: curl -H "Authorization: Bearer ` + token + `" https://<service>.lab/`)
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

func cmdPolicy(client *api.Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: labnet policy check|test|apply <file>, or labnet policy status")
	}
	if args[0] == "status" {
		return cmdPolicyStatus(client)
	}
	if len(args) != 2 {
		return fmt.Errorf("usage: labnet policy %s <file>", args[0])
	}
	src, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("reading %s: %w", args[1], err)
	}

	switch args[0] {
	case "check":
		resp, err := client.PolicyCheck(string(src))
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Println("ok")
		printRuleNames(resp.Rules)
		return nil

	case "test":
		resp, err := client.PolicyTest(string(src))
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Printf("HTTP: would deny %d of %d requests currently in the journal\n", resp.HTTP.Matched, resp.HTTP.Total)
		printByRule(resp.HTTP.ByRule)
		fmt.Printf("DNS:  would block %d of %d queries currently in the journal\n", resp.DNS.Matched, resp.DNS.Total)
		printByRule(resp.DNS.ByRule)
		return nil

	case "apply":
		resp, err := client.PolicyApply(string(src))
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Println("applied")
		printRuleNames(resp.Rules)
		return nil

	default:
		return fmt.Errorf("usage: labnet policy check|test|apply <file>, or labnet policy status")
	}
}

func cmdPolicyStatus(client *api.Client) error {
	resp, err := client.PolicyStatus()
	if err != nil {
		return err
	}
	printRuleNames(resp.Rules)
	return nil
}

func printRuleNames(rules map[string][]string) {
	for _, category := range []string{"deny_", "allow_", "public_", "block_", "alert_"} {
		names := rules[category]
		if len(names) == 0 {
			continue
		}
		fmt.Printf("  %-8s %s\n", category, strings.Join(names, ", "))
	}
}

func printByRule(byRule map[string]int) {
	for rule, n := range byRule {
		fmt.Printf("    %-30s %d\n", rule, n)
	}
}

func cmdAlerts(client *api.Client) error {
	alerts, err := client.Alerts()
	if err != nil {
		return err
	}
	if len(alerts) == 0 {
		fmt.Println("no alerts")
		return nil
	}
	for _, a := range alerts {
		fmt.Printf("[%s] %-24s %s: %s\n", time.UnixMilli(int64(a.TS)).Format(time.RFC3339), a.Rule, a.Schema, a.Summary)
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
	for name, fields := range st.Schemas {
		var parts []string
		for _, f := range fields {
			parts = append(parts, f.Name+":"+f.Type)
		}
		fmt.Printf("  %-12s %s\n", name, strings.Join(parts, " "))
	}
	return nil
}
