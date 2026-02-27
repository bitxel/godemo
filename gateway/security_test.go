package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --- IP Filtering Tests ---

func TestIPDenyList(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.denyIPs = map[string]struct{}{"127.0.0.1": {}}

	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for denied IP, got %d", resp.StatusCode)
	}
}

func TestIPAllowList(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.allowIPs = map[string]struct{}{"192.168.1.1": {}}

	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 for non-allowed IP, got %d body=%s", resp.StatusCode, string(body))
	}
}

func TestIPAllowListEmpty(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	if session.SessionID == "" {
		t.Fatal("expected session to be created when allowIPs is empty (allow-all)")
	}
}

// --- Auth Tests ---

func TestHeartbeatWrongToken(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions/"+session.SessionID+"/heartbeat", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d", resp.StatusCode)
	}
}

func TestDeleteSessionWrongToken(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/sessions/"+session.SessionID, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d", resp.StatusCode)
	}
}

func TestHeartbeatNonexistentSession(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions/ses_nonexistent/heartbeat", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDeleteNonexistentSession(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/sessions/ses_nonexistent", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestWSConnectWrongToken(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/tunnel/ws?session_id=" + session.SessionID + "&token=wrong"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected WS upgrade to fail with wrong token")
	}
	if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestWSConnectMissingParams(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/tunnel/ws"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected WS upgrade to fail without params")
	}
	if resp != nil && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWSConnectNonexistentSession(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/tunnel/ws?session_id=ses_fake&token=tok_fake"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected WS upgrade to fail for nonexistent session")
	}
	if resp != nil && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// --- Rate Limiting & Session Limit Tests ---

func TestMaxSessionsPerIP(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.maxSessionsPerIP = 2

	_ = createSession(t, ts.URL)
	_ = createSession(t, ts.URL)

	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when max sessions reached, got %d", resp.StatusCode)
	}
}

func TestMaxSessionsPerIPRecoversAfterDelete(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.maxSessionsPerIP = 1

	session := createSession(t, ts.URL)

	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/sessions/"+session.SessionID, nil)
	delReq.Header.Set("Authorization", "Bearer "+session.Token)
	delResp, _ := http.DefaultClient.Do(delReq)
	_ = delResp.Body.Close()

	session2 := createSession(t, ts.URL)
	if session2.SessionID == "" {
		t.Fatal("expected to create session after deletion freed up slot")
	}
}

// --- Input Validation Tests ---

func TestCreateSessionInvalidJSON(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewBufferString(`{not json}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestCreateSessionEmptyBody(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201 for empty body (defaults), got %d body=%s", resp.StatusCode, string(body))
	}
}

func TestCreateSessionCustomTTL(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{"ttl_seconds": 60})
	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	var session createSessionResponse
	_ = json.NewDecoder(resp.Body).Decode(&session)
	if session.TTLSeconds != 60 {
		t.Fatalf("expected TTL 60, got %d", session.TTLSeconds)
	}
}

func TestCreateSessionTTLCappedAtServerMax(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.sessionTTL = 120 * time.Second

	body, _ := json.Marshal(map[string]any{"ttl_seconds": 99999})
	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	var session createSessionResponse
	_ = json.NewDecoder(resp.Body).Decode(&session)
	if session.TTLSeconds != 120 {
		t.Fatalf("expected TTL capped at 120, got %d", session.TTLSeconds)
	}
}

func TestCreateSessionMethodNotAllowed(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/sessions")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET on create endpoint, got %d", resp.StatusCode)
	}
}

func TestLongFingerprint(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	longFP := strings.Repeat("a", 10000)
	body, _ := json.Marshal(map[string]any{
		"fingerprint": longFP,
		"port":        3000,
	})
	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 even with long fingerprint, got %d", resp.StatusCode)
	}
}

// --- Session Action Routing Tests ---

func TestSessionActionEmptyPath(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for empty session path, got %d", resp.StatusCode)
	}
}

func TestSessionActionUnsupportedAction(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions/"+session.SessionID+"/unknown", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unsupported action, got %d", resp.StatusCode)
	}
}

func TestSessionActionDeleteWithExtraPath(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/sessions/"+session.SessionID+"/extra", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for DELETE with extra path, got %d", resp.StatusCode)
	}
}

func TestSessionActionMethodNotAllowed(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/sessions/"+session.SessionID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for PUT, got %d", resp.StatusCode)
	}
}

// --- Public Request Edge Cases ---

func TestPublicRequestExpiredSession(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.sessionTTL = 1 * time.Millisecond

	session := createSession(t, ts.URL)
	time.Sleep(10 * time.Millisecond)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("expected 410 for expired session, got %d", resp.StatusCode)
	}
}

func TestPublicRequestDisconnectedTunnel(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/test", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for disconnected tunnel, got %d", resp.StatusCode)
	}
}

func TestPublicRequestSDKDisconnectsMidFlight(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.requestTimeout = 2 * time.Second

	session := createSession(t, ts.URL)
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}

	go func() {
		var msg tunnelMessage
		_ = conn.ReadJSON(&msg)
		conn.Close()
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/test", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected error status for mid-flight disconnect, got %d", resp.StatusCode)
	}
}

func TestPublicRequestTimeout(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.requestTimeout = 200 * time.Millisecond

	session := createSession(t, ts.URL)
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
	defer conn.Close()

	go func() {
		var msg tunnelMessage
		_ = conn.ReadJSON(&msg)
		// intentionally don't respond, causing timeout
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/slow", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 for timeout, got %d", resp.StatusCode)
	}
}

func TestPublicRequestMaxBodyLimit(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.maxHTTPBodyBytes = 100

	session := createSession(t, ts.URL)
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
	defer conn.Close()

	go func() {
		for {
			var msg tunnelMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
		}
	}()

	bigBody := strings.NewReader(strings.Repeat("x", 200))
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/upload", bigBody)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", resp.StatusCode)
	}
}

// --- Healthz ---

func TestHealthz(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/healthz")
	if err != nil {
		t.Fatalf("healthz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body)
	}
}

// --- Concurrent Tests ---

func TestConcurrentSessionCreation(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.createPerMinute = 1000
	s.maxSessionsPerIP = 100

	var wg sync.WaitGroup
	errors := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewBufferString(`{}`))
			if err != nil {
				errors <- fmt.Errorf("request failed: %w", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				body, _ := io.ReadAll(resp.Body)
				errors <- fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
			}
		}()
	}
	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent creation error: %v", err)
	}
}

func TestConcurrentHeartbeats(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions/"+session.SessionID+"/heartbeat", nil)
			req.Header.Set("Authorization", "Bearer "+session.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("heartbeat failed: %v", err)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200, got %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentCreateAndDelete(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.createPerMinute = 1000
	s.maxSessionsPerIP = 100

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session := createSession(t, ts.URL)
			delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/sessions/"+session.SessionID, nil)
			delReq.Header.Set("Authorization", "Bearer "+session.Token)
			resp, _ := http.DefaultClient.Do(delReq)
			if resp != nil {
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	s.mu.RLock()
	remaining := len(s.sessions)
	s.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("expected 0 remaining sessions after all deletes, got %d", remaining)
	}
}

// --- Session Expiry Tests ---

func TestWSConnectExpiredSession(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.sessionTTL = 1 * time.Millisecond

	session := createSession(t, ts.URL)
	time.Sleep(10 * time.Millisecond)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/tunnel/ws?session_id=" + session.SessionID + "&token=" + session.Token
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected WS upgrade to fail for expired session")
	}
	if resp != nil && resp.StatusCode != http.StatusGone {
		t.Fatalf("expected 410, got %d", resp.StatusCode)
	}
}

func TestHeartbeatExtendsTTL(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.sessionTTL = 10 * time.Second

	session := createSession(t, ts.URL)

	beforeHB := time.Now()
	hbReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions/"+session.SessionID+"/heartbeat", nil)
	hbReq.Header.Set("Authorization", "Bearer "+session.Token)
	hbResp, err := http.DefaultClient.Do(hbReq)
	if err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	defer hbResp.Body.Close()
	var hb heartbeatResponse
	_ = json.NewDecoder(hbResp.Body).Decode(&hb)

	exp, _ := time.Parse(time.RFC3339, hb.ExpiresAt)
	expectedMin := beforeHB.Add(s.sessionTTL - 1*time.Second)
	if exp.Before(expectedMin) {
		t.Fatalf("heartbeat should have extended expiry to ~now+10s, got %s (expected at least %s)", hb.ExpiresAt, expectedMin.UTC().Format(time.RFC3339))
	}
}

// --- WebSocket SDK Reconnect ---

func TestSDKWebSocketReconnect(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)

	conn1, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("first WS connection failed: %v", err)
	}

	conn2, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("second WS connection failed: %v", err)
	}

	_, _, err = conn1.ReadMessage()
	if err == nil {
		t.Fatal("first connection should have been closed on reconnect")
	}
	conn2.Close()
}

// --- Bridge/WS Close via SDK ---

func TestWSCloseFromSDK(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)

	sdkConn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
	defer sdkConn.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	host := fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	header := http.Header{"Host": []string{host}}

	publicConn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial public ws failed: %v", err)
	}
	defer publicConn.Close()

	_ = sdkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var openMsg tunnelMessage
	if err := sdkConn.ReadJSON(&openMsg); err != nil {
		t.Fatalf("read ws_open failed: %v", err)
	}

	closeMsg := tunnelMessage{
		Type:         "ws_close",
		ConnectionID: openMsg.ConnectionID,
		Code:         1000,
		Reason:       "test close",
	}
	if err := sdkConn.WriteJSON(closeMsg); err != nil {
		t.Fatalf("write ws_close failed: %v", err)
	}

	_ = publicConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = publicConn.ReadMessage()
	if err == nil {
		t.Fatal("public WS should have received close after SDK sends ws_close")
	}
}

// --- SDK Error Message Handling ---

func TestSDKErrorMessage(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	errMsg := tunnelMessage{Type: "error", Message: "test error"}
	_ = conn.WriteJSON(errMsg)
	time.Sleep(50 * time.Millisecond)
}

// --- SDK Ping/Pong ---

func TestSDKPingPong(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	_ = conn.WriteJSON(tunnelMessage{Type: "ping"})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pong tunnelMessage
	if err := conn.ReadJSON(&pong); err != nil {
		t.Fatalf("read pong failed: %v", err)
	}
	if pong.Type != "pong" {
		t.Fatalf("expected pong, got %s", pong.Type)
	}
}

// --- Tunnel Session Struct Tests ---

func TestTunnelSessionPendingOperations(t *testing.T) {
	session := &tunnelSession{
		pending: make(map[string]chan tunnelMessage),
		wsConns: make(map[string]*bridgeConn),
	}

	ch := make(chan tunnelMessage, 1)
	session.addPending("req1", ch)
	session.addPending("req2", make(chan tunnelMessage, 1))

	got := session.popPending("req1")
	if got != ch {
		t.Fatal("popPending should return the correct channel")
	}

	got2 := session.popPending("req1")
	if got2 != nil {
		t.Fatal("second popPending should return nil")
	}

	session.failAllPending(tunnelMessage{Type: "error", Message: "fail"})
}

func TestTunnelSessionConnLifecycle(t *testing.T) {
	session := &tunnelSession{
		pending: make(map[string]chan tunnelMessage),
		wsConns: make(map[string]*bridgeConn),
	}

	if session.getConn() != nil {
		t.Fatal("initial conn should be nil")
	}

	session.clearConn()
	if session.getConn() != nil {
		t.Fatal("clearConn on nil should be safe")
	}
}

func TestTunnelSessionSendWithoutConn(t *testing.T) {
	session := &tunnelSession{
		pending: make(map[string]chan tunnelMessage),
		wsConns: make(map[string]*bridgeConn),
	}

	err := session.send(tunnelMessage{Type: "test"})
	if err == nil || err.Error() != "sdk websocket not connected" {
		t.Fatalf("expected 'sdk websocket not connected', got %v", err)
	}
}

// --- ipAllowed ---

func TestIPAllowedLogic(t *testing.T) {
	s := &server{
		allowIPs: map[string]struct{}{},
		denyIPs:  map[string]struct{}{},
	}

	if !s.ipAllowed("1.2.3.4") {
		t.Fatal("empty allow+deny should allow all")
	}

	s.denyIPs["1.2.3.4"] = struct{}{}
	if s.ipAllowed("1.2.3.4") {
		t.Fatal("denied IP should not be allowed")
	}
	if !s.ipAllowed("5.6.7.8") {
		t.Fatal("non-denied IP should be allowed")
	}

	s.allowIPs["10.0.0.1"] = struct{}{}
	if s.ipAllowed("5.6.7.8") {
		t.Fatal("with allowlist, non-listed IP should be blocked")
	}
	if !s.ipAllowed("10.0.0.1") {
		t.Fatal("allow-listed IP should be allowed")
	}

	s.denyIPs["10.0.0.1"] = struct{}{}
	if s.ipAllowed("10.0.0.1") {
		t.Fatal("deny should override allow")
	}
}

// --- FindSessionByHost ---

func TestFindSessionByHost(t *testing.T) {
	s, _ := newTestServer()

	if got := s.findSessionByHost("unrelated.example.com"); got != nil {
		t.Fatal("unrelated host should return nil")
	}

	if got := s.findSessionByHost(s.rootDomain); got != nil {
		t.Fatal("root domain (no subdomain) should return nil")
	}

	if got := s.findSessionByHost("sub." + s.rootDomain); got != nil {
		t.Fatal("non-existent subdomain should return nil")
	}

	session := &tunnelSession{
		id:        "ses_test",
		subdomain: "myhost",
		pending:   make(map[string]chan tunnelMessage),
		wsConns:   make(map[string]*bridgeConn),
	}
	s.sessions["ses_test"] = session
	s.bySubdomain["myhost"] = "ses_test"

	got := s.findSessionByHost("myhost." + s.rootDomain)
	if got == nil || got.id != "ses_test" {
		t.Fatal("expected to find session by subdomain host")
	}
}

// --- allowCreate ---

func TestAllowCreateRateWindow(t *testing.T) {
	s := &server{
		createPerMinute: 2,
		ipCreates:       make(map[string]*createWindow),
		sessions:        make(map[string]*tunnelSession),
		bySubdomain:     make(map[string]string),
		ipSessionNum:    make(map[string]int),
	}
	s.mu.Lock()
	s.mu.Unlock()

	if !s.allowCreate("10.0.0.1") {
		t.Fatal("first create should be allowed")
	}
	if !s.allowCreate("10.0.0.1") {
		t.Fatal("second create should be allowed")
	}
	if s.allowCreate("10.0.0.1") {
		t.Fatal("third create should be rate-limited")
	}
	if !s.allowCreate("10.0.0.2") {
		t.Fatal("different IP should be allowed")
	}
}
