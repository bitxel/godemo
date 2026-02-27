package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestFixWSScheme(t *testing.T) {
	tests := []struct {
		name       string
		wsURL      string
		gatewayURL string
		want       string
	}{
		{"https gateway upgrades ws to wss", "ws://gw.test/ws", "https://gw.test", "wss://gw.test/ws"},
		{"http gateway downgrades wss to ws", "wss://gw.test/ws", "http://gw.test", "ws://gw.test/ws"},
		{"https gateway leaves wss alone", "wss://gw.test/ws", "https://gw.test", "wss://gw.test/ws"},
		{"http gateway leaves ws alone", "ws://gw.test/ws", "http://gw.test", "ws://gw.test/ws"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fixWSScheme(tt.wsURL, tt.gatewayURL)
			if got != tt.want {
				t.Errorf("fixWSScheme(%q, %q) = %q; want %q", tt.wsURL, tt.gatewayURL, got, tt.want)
			}
		})
	}
}

func TestFixPublicScheme(t *testing.T) {
	tests := []struct {
		name       string
		publicURL  string
		gatewayURL string
		want       string
	}{
		{"https gateway upgrades http to https", "http://dm-abc.test", "https://gw.test", "https://dm-abc.test"},
		{"http gateway leaves http alone", "http://dm-abc.test", "http://gw.test", "http://dm-abc.test"},
		{"https gateway leaves https alone", "https://dm-abc.test", "https://gw.test", "https://dm-abc.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fixPublicScheme(tt.publicURL, tt.gatewayURL)
			if got != tt.want {
				t.Errorf("fixPublicScheme(%q, %q) = %q; want %q", tt.publicURL, tt.gatewayURL, got, tt.want)
			}
		})
	}
}

func TestMachineFingerprint(t *testing.T) {
	fp := machineFingerprint()
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d; want 64 (SHA-256 hex)", len(fp))
	}
	fp2 := machineFingerprint()
	if fp != fp2 {
		t.Error("fingerprint not deterministic")
	}
}

func TestCreateSession(t *testing.T) {
	mockGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sessions" {
			http.Error(w, "not found", 404)
			return
		}
		var req createSessionRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Fingerprint == "" {
			t.Error("expected non-empty fingerprint")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createSessionResponse{
			SessionID:  "ses_test123",
			Subdomain:  "dm-abc",
			PublicURL:  "http://dm-abc.localhost",
			WSEndpoint: "ws://localhost/api/v1/tunnel/ws?session_id=ses_test123",
			Token:      "tok_abc",
			TTLSeconds: 7200,
			ExpiresAt:  "2099-01-01T00:00:00Z",
		})
	}))
	defer mockGateway.Close()

	tun := newTunnel(mockGateway.URL, "127.0.0.1", 3000)
	if err := tun.createSession(); err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if tun.sessionID != "ses_test123" {
		t.Errorf("sessionID = %q; want %q", tun.sessionID, "ses_test123")
	}
	if tun.token != "tok_abc" {
		t.Errorf("token = %q; want %q", tun.token, "tok_abc")
	}
	if tun.publicURL != "http://dm-abc.localhost" {
		t.Errorf("publicURL = %q; want %q", tun.publicURL, "http://dm-abc.localhost")
	}
}

func TestCreateSessionHTTPError(t *testing.T) {
	mockGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "rate limited"})
	}))
	defer mockGateway.Close()

	tun := newTunnel(mockGateway.URL, "127.0.0.1", 3000)
	err := tun.createSession()
	if err == nil {
		t.Fatal("expected error from createSession")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should contain 429; got %v", err)
	}
}

func TestDeleteSession(t *testing.T) {
	deleted := false
	mockGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/sessions/ses_del") {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer tok_del" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			deleted = true
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockGateway.Close()

	tun := newTunnel(mockGateway.URL, "127.0.0.1", 3000)
	tun.sessionID = "ses_del"
	tun.token = "tok_del"
	tun.deleteSession()
	if !deleted {
		t.Error("deleteSession did not call the API")
	}
}

func TestNewTunnelTrimsSlash(t *testing.T) {
	tun := newTunnel("http://example.com/", "127.0.0.1", 8080)
	if strings.HasSuffix(tun.gatewayURL, "/") {
		t.Errorf("gatewayURL should not end with /; got %q", tun.gatewayURL)
	}
}

func TestPathWithQuery(t *testing.T) {
	if got := pathWithQuery("/foo", "a=1"); got != "/foo?a=1" {
		t.Errorf("pathWithQuery = %q; want /foo?a=1", got)
	}
	if got := pathWithQuery("/foo", ""); got != "/foo" {
		t.Errorf("pathWithQuery = %q; want /foo", got)
	}
}

func TestEventLoopMalformedJSON(t *testing.T) {
	// Start a mock WS server that sends malformed JSON
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Send malformed JSON
		_ = conn.WriteMessage(websocket.TextMessage, []byte("this is not json{{{"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	tun := newTunnel("http://localhost", "127.0.0.1", 3000)
	tun.ws = conn

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		tun.eventLoop(ctx)
		close(done)
	}()

	select {
	case <-done:
		// eventLoop should exit gracefully on malformed JSON
	case <-time.After(5 * time.Second):
		t.Fatal("eventLoop did not exit after malformed JSON")
	}
}

func TestEventLoopUnknownMessageType(t *testing.T) {
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		msg := tunnelMessage{Type: "unknown_type_xyz"}
		_ = conn.WriteJSON(msg)
		// Then close
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	tun := newTunnel("http://localhost", "127.0.0.1", 3000)
	tun.ws = conn

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		tun.eventLoop(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Should exit gracefully after unknown type + connection close
	case <-time.After(5 * time.Second):
		t.Fatal("eventLoop did not exit after unknown message type")
	}
}

func TestSchemeFixPreservesPath(t *testing.T) {
	got := fixWSScheme("ws://gw.test:8080/api/v1/tunnel/ws?session_id=ses_abc", "https://gw.test")
	want := "wss://gw.test:8080/api/v1/tunnel/ws?session_id=ses_abc"
	if got != want {
		t.Errorf("fixWSScheme did not preserve path; got %q, want %q", got, want)
	}
}
