package sse

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBroadcastDeliversToConnectedClient(t *testing.T) {
	hub := NewHub()
	srv := httptest.NewServer(hub)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && hub.ClientCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if hub.ClientCount() != 1 {
		t.Fatalf("ClientCount = %d, want 1", hub.ClientCount())
	}

	hub.Broadcast("dns", map[string]any{"name": "app.lab.", "blocked": false})

	reader := bufio.NewReader(resp.Body)
	var eventLine, dataLine string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading SSE stream: %v", err)
		}
		line = strings.TrimRight(line, "\n")
		if strings.HasPrefix(line, "event: ") {
			eventLine = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if eventLine != "dns" {
		t.Errorf("event = %q, want dns", eventLine)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(dataLine), &got); err != nil {
		t.Fatalf("unmarshaling data line %q: %v", dataLine, err)
	}
	if got["name"] != "app.lab." || got["blocked"] != false {
		t.Errorf("data = %+v, want name=app.lab. blocked=false", got)
	}
}

func TestClientCountDropsOnDisconnect(t *testing.T) {
	hub := NewHub()
	srv := httptest.NewServer(hub)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && hub.ClientCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	resp.Body.Close()

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && hub.ClientCount() != 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if hub.ClientCount() != 0 {
		t.Fatalf("ClientCount = %d after disconnect, want 0", hub.ClientCount())
	}
}

func TestBroadcastWithNoClientsDoesNotBlock(t *testing.T) {
	hub := NewHub()
	done := make(chan struct{})
	go func() {
		hub.Broadcast("dns", map[string]any{"x": 1})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Broadcast blocked with no clients connected")
	}
}
