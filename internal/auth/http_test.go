package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPairHandlerSuccess(t *testing.T) {
	s := openTestStore(t)
	code, err := s.CreatePairingCode(t.Context(), time.Hour)
	if err != nil {
		t.Fatalf("CreatePairingCode: %v", err)
	}

	var events []AuthEvent
	h := NewPairHandler(s, "lab", func(e AuthEvent) { events = append(events, e) })

	form := url.Values{"code": {code}, "name": {"my-phone"}}
	req := httptest.NewRequest(http.MethodPost, PairPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "Domain=lab") {
		t.Errorf("Set-Cookie header = %q, want it to contain Domain=lab", setCookie)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no labnet_device cookie set")
	}

	gate := &Gate{Store: s}
	authReq := httptest.NewRequest(http.MethodGet, "https://app.lab/", nil)
	authReq.AddCookie(cookie)
	_, name, ok := gate.Authenticate(authReq)
	if !ok || name != "my-phone" {
		t.Errorf("Gate.Authenticate via cookie = (%q, %v), want (my-phone, true)", name, ok)
	}

	if len(events) != 1 || !events[0].OK || events[0].Kind != "device-pair" {
		t.Errorf("events = %+v, want one ok=true device-pair event", events)
	}
}

func TestPairHandlerBadCode(t *testing.T) {
	s := openTestStore(t)
	var events []AuthEvent
	h := NewPairHandler(s, "lab", func(e AuthEvent) { events = append(events, e) })

	form := url.Values{"code": {"999999"}, "name": {"x"}}
	req := httptest.NewRequest(http.MethodPost, PairPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if len(events) != 1 || events[0].OK {
		t.Errorf("events = %+v, want one ok=false event", events)
	}
}

func TestGateAuthenticateBearer(t *testing.T) {
	s := openTestStore(t)
	code, _ := s.CreatePairingCode(t.Context(), time.Hour)
	_, token, err := s.RedeemPairingCode(t.Context(), code, "curl-box")
	if err != nil {
		t.Fatalf("RedeemPairingCode: %v", err)
	}

	gate := &Gate{Store: s}
	req := httptest.NewRequest(http.MethodGet, "https://app.lab/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	_, name, ok := gate.Authenticate(req)
	if !ok || name != "curl-box" {
		t.Errorf("Authenticate = (%q, %v), want (curl-box, true)", name, ok)
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://app.lab/", nil)
	req2.Header.Set("Authorization", "Bearer wrong-token")
	if _, _, ok := gate.Authenticate(req2); ok {
		t.Error("Authenticate succeeded with a wrong token")
	}

	req3 := httptest.NewRequest(http.MethodGet, "https://app.lab/", nil)
	if _, _, ok := gate.Authenticate(req3); ok {
		t.Error("Authenticate succeeded with no credential at all")
	}
}
