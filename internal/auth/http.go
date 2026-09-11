package auth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// scoped by the caller to the whole .lab domain so one pairing covers every service
const CookieName = "labnet_device"

type Gate struct {
	Store *Store
}

func (g *Gate) Authenticate(r *http.Request) (deviceID, deviceName string, ok bool) {
	if tok := bearerToken(r); tok != "" {
		if id, name, found, err := g.Store.AuthenticateToken(r.Context(), tok); err == nil && found {
			return id, name, true
		}
	}
	if c, err := r.Cookie(CookieName); err == nil {
		if id, name, found, err := g.Store.AuthenticateToken(r.Context(), c.Value); err == nil && found {
			return id, name, true
		}
	}
	return "", "", false
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimPrefix(h, prefix)
	}
	return ""
}

const PairPath = "/_labnet/pair"

// defined here instead of importing schema/journal, to keep this package's deps light
type AuthEvent struct {
	TS     uint64
	Client net.IP
	Device string
	Kind   string
	OK     bool
}

func NewPairHandler(store *Store, cookieDomain string, onEvent func(AuthEvent)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PairPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, pairFormHTML)
	})
	mux.HandleFunc("POST "+PairPath, func(w http.ResponseWriter, r *http.Request) {
		handlePair(w, r, store, cookieDomain, onEvent)
	})
	return mux
}

func handlePair(w http.ResponseWriter, r *http.Request, store *Store, cookieDomain string, onEvent func(AuthEvent)) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	name := strings.TrimSpace(r.FormValue("name"))

	id, token, err := store.RedeemPairingCode(r.Context(), code, name)
	ok := err == nil
	if onEvent != nil {
		onEvent(AuthEvent{TS: uint64(time.Now().UnixMilli()), Client: clientIP(r), Device: name, Kind: "device-pair", OK: ok})
	}
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, pairErrorHTML, err)
		return
	}

	// domain cookie: no leading dot needed, rfc 6265 already matches subdomains
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Domain: cookieDomain, Path: "/",
		MaxAge: 365 * 24 * 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, pairSuccessHTML, id, r.FormValue("name"))
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

const pairFormHTML = `<!doctype html>
<html><head><title>Pair this device — labnet</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:24rem;margin:3rem auto;padding:0 1rem}
input{font-size:1.2rem;padding:.5rem;width:100%;box-sizing:border-box;margin-bottom:.75rem}
button{font-size:1.1rem;padding:.5rem 1rem;width:100%}
</style></head>
<body>
<h1>Pair this device</h1>
<p>Enter the pairing code shown by <code>labnetd</code> (or minted by an already-paired device).</p>
<form method="POST" action="` + PairPath + `">
<label>Code<br><input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autofocus required></label>
<label>Name this device<br><input name="name" placeholder="e.g. abd's phone"></label>
<button type="submit">Pair</button>
</form>
</body></html>`

const pairSuccessHTML = `<!doctype html>
<html><head><title>Paired — labnet</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;max-width:24rem;margin:3rem auto;padding:0 1rem">
<h1>Paired ✓</h1>
<p>Device <b>%[2]s</b> (id <code>%[1]s</code>) is paired. Every *.lab service is now reachable from this device.</p>
</body></html>`

const pairErrorHTML = `<!doctype html>
<html><head><title>Pairing failed — labnet</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;max-width:24rem;margin:3rem auto;padding:0 1rem">
<h1>Pairing failed</h1>
<p>%s</p>
<p><a href="` + PairPath + `">Try again</a></p>
</body></html>`
