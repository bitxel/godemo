package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type tunnel struct {
	gatewayURL     string
	localHost      string
	localPort      int
	requestTimeout float64
	allowedPaths   []string

	sessionID  string
	token      string
	publicURL  string
	wsEndpoint string

	ws      *websocket.Conn
	wsMu    sync.Mutex

	bridges   map[string]*websocket.Conn
	bridgesMu sync.Mutex

	cancel context.CancelFunc
}

func newTunnel(gatewayURL string, localHost string, localPort int) *tunnel {
	return &tunnel{
		gatewayURL:     strings.TrimRight(gatewayURL, "/"),
		localHost:      localHost,
		localPort:      localPort,
		requestTimeout: 20.0,
		bridges:        make(map[string]*websocket.Conn),
	}
}

func (t *tunnel) createSession() error {
	fingerprint := machineFingerprint()
	reqBody := createSessionRequest{
		Fingerprint:  fingerprint,
		Port:         t.localPort,
		AllowedPaths: t.allowedPaths,
	}
	body, _ := json.Marshal(reqBody)

	logInfo("creating session at %s", t.gatewayURL)
	resp, err := http.Post(t.gatewayURL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create session: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var session createSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return fmt.Errorf("decode session: %w", err)
	}

	t.sessionID = session.SessionID
	t.token = session.Token
	t.wsEndpoint = fixWSScheme(session.WSEndpoint, t.gatewayURL)
	t.publicURL = fixPublicScheme(session.PublicURL, t.gatewayURL)

	logInfo("session created id=%s public_url=%s", t.sessionID, t.publicURL)
	return nil
}

func (t *tunnel) deleteSession() {
	if t.sessionID == "" || t.token == "" {
		return
	}
	logInfo("deleting session %s", t.sessionID)
	req, err := http.NewRequest(http.MethodDelete, t.gatewayURL+"/api/v1/sessions/"+t.sessionID, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func (t *tunnel) connect(ctx context.Context) error {
	logInfo("connecting tunnel ws %s", t.wsEndpoint)
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, t.wsEndpoint, nil)
	if err != nil {
		return fmt.Errorf("ws connect: %w", err)
	}
	conn.SetReadLimit(8 * 1024 * 1024)
	t.ws = conn

	authMsg := tunnelMessage{Type: "auth", Token: t.token}
	if err := conn.WriteJSON(authMsg); err != nil {
		conn.Close()
		return fmt.Errorf("ws auth: %w", err)
	}

	logInfo("tunnel ws connected, session=%s", t.sessionID)
	return nil
}

func (t *tunnel) wsSend(msg tunnelMessage) error {
	t.wsMu.Lock()
	defer t.wsMu.Unlock()
	return t.ws.WriteJSON(msg)
}

func (t *tunnel) eventLoop(ctx context.Context) {
	ws := t.ws
	loopCtx, loopCancel := context.WithCancel(ctx)
	defer loopCancel()

	go func() {
		<-loopCtx.Done()
		if ws != nil {
			_ = ws.Close()
		}
	}()

	for {
		var msg tunnelMessage
		if err := ws.ReadJSON(&msg); err != nil {
			if ctx.Err() != nil {
				return
			}
			logError("tunnel ws read error: %v", err)
			return
		}

		switch msg.Type {
		case "request":
			go t.handleHTTPRequest(msg)
		case "ws_open":
			t.handleWSOpen(ctx, msg)
		case "ws_data":
			t.handleWSData(msg)
		case "ws_close":
			t.handleWSClose(msg)
		case "ping":
			_ = t.wsSend(tunnelMessage{Type: "pong"})
		case "error":
			logWarn("gateway error: %s", msg.Message)
		}
	}
}

func (t *tunnel) runWithReconnect(ctx context.Context) {
	backoff := 1 * time.Second
	attempt := 0

	for {
		if ctx.Err() != nil {
			return
		}

		if attempt > 0 {
			logInfo("reconnecting tunnel ws in %s...", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = backoff * 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}

		attempt++

		if err := t.connect(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			logError("reconnect failed: %v", err)
			continue
		}

		backoff = 1 * time.Second
		attempt = 0
		t.eventLoop(ctx)

		if ctx.Err() != nil {
			return
		}
	}
}

func (t *tunnel) close() {
	if t.ws != nil {
		_ = t.ws.Close()
	}

	t.bridgesMu.Lock()
	for id, conn := range t.bridges {
		_ = conn.Close()
		delete(t.bridges, id)
	}
	t.bridgesMu.Unlock()

	t.deleteSession()
}

func machineFingerprint() string {
	hostname, _ := os.Hostname()
	username := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	ifaces, _ := net.Interfaces()
	mac := ""
	for _, iface := range ifaces {
		if iface.HardwareAddr != nil && len(iface.HardwareAddr) > 0 {
			mac = iface.HardwareAddr.String()
			break
		}
	}
	raw := fmt.Sprintf("%s:%s:%s", hostname, mac, username)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)
}

func fixWSScheme(wsURL, gatewayURL string) string {
	if strings.HasPrefix(gatewayURL, "https://") && strings.HasPrefix(wsURL, "ws://") {
		return "wss://" + wsURL[len("ws://"):]
	}
	if strings.HasPrefix(gatewayURL, "http://") && strings.HasPrefix(wsURL, "wss://") {
		return "ws://" + wsURL[len("wss://"):]
	}
	return wsURL
}

func fixPublicScheme(publicURL, gatewayURL string) string {
	if strings.HasPrefix(gatewayURL, "https://") && strings.HasPrefix(publicURL, "http://") {
		return "https://" + publicURL[len("http://"):]
	}
	return publicURL
}
