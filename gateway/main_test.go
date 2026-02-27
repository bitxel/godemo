package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newTestServer() (*server, *httptest.Server) {
	s := &server{
		addr:             ":0",
		rootDomain:       "0x0f.me",
		sessionTTL:       defaultSessionTTL,
		requestTimeout:   defaultRequestTimeout,
		maxSessionsPerIP: 10,
		createPerMinute:  100,
		maxHTTPBodyBytes: defaultMaxHTTPBodyBytes,
		maxWSMessageSize: defaultMaxWSMessageBytes,
		trustProxy:       false,
		allowIPs:         map[string]struct{}{},
		denyIPs:          map[string]struct{}{},
		sessions:         make(map[string]*tunnelSession),
		bySubdomain:      make(map[string]string),
		ipSessionNum:     make(map[string]int),
		ipCreates:        make(map[string]*createWindow),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/healthz", s.handleHealthz)
	mux.HandleFunc("/api/v1/sessions", s.handleCreateSession)
	mux.HandleFunc("/api/v1/sessions/", s.handleSessionAction)
	mux.HandleFunc("/api/v1/tunnel/ws", s.handleTunnelWS)
	mux.HandleFunc("/", s.handlePublicRequest)

	return s, httptest.NewServer(mux)
}

func createSession(t *testing.T, baseURL string) createSessionResponse {
	t.Helper()
	reqBody := bytes.NewBufferString(`{}`)
	resp, err := http.Post(baseURL+"/api/v1/sessions", "application/json", reqBody)
	if err != nil {
		t.Fatalf("create session request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create session status=%d body=%s", resp.StatusCode, string(body))
	}
	var out createSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode session response failed: %v", err)
	}
	return out
}

func dialSDKWS(t *testing.T, tsURL string, session createSessionResponse) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(tsURL, "http") + "/api/v1/tunnel/ws?session_id=" + session.SessionID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
	authMsg := tunnelMessage{Type: "auth", Token: session.Token}
	if err := conn.WriteJSON(authMsg); err != nil {
		conn.Close()
		t.Fatalf("write auth message failed: %v", err)
	}
	return conn
}

func TestSessionLifecycle_CreateHeartbeatDelete(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)

	hbReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions/"+session.SessionID+"/heartbeat", nil)
	hbReq.Header.Set("Authorization", "Bearer "+session.Token)
	hbResp, err := http.DefaultClient.Do(hbReq)
	if err != nil {
		t.Fatalf("heartbeat request failed: %v", err)
	}
	if hbResp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat status=%d", hbResp.StatusCode)
	}
	_ = hbResp.Body.Close()

	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/sessions/"+session.SessionID, nil)
	delReq.Header.Set("Authorization", "Bearer "+session.Token)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status=%d", delResp.StatusCode)
	}
	_ = delResp.Body.Close()

	hb2Req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/sessions/"+session.SessionID+"/heartbeat", nil)
	hb2Req.Header.Set("Authorization", "Bearer "+session.Token)
	hb2Resp, err := http.DefaultClient.Do(hb2Req)
	if err != nil {
		t.Fatalf("second heartbeat failed: %v", err)
	}
	defer hb2Resp.Body.Close()
	if hb2Resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", hb2Resp.StatusCode)
	}
}

func TestCreateSessionRateLimit(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.createPerMinute = 1

	_ = createSession(t, ts.URL)
	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatalf("second create request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestPublicHTTPForwarding(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		var req tunnelMessage
		if err := conn.ReadJSON(&req); err != nil {
			t.Errorf("read forwarded request failed: %v", err)
			return
		}
		if req.Type != "request" {
			t.Errorf("expected request message, got %s", req.Type)
			return
		}
		resp := tunnelMessage{
			Type:      "response",
			RequestID: req.RequestID,
			Status:    http.StatusOK,
			Headers:   map[string][]string{"content-type": {"text/plain"}},
			BodyB64:   base64.StdEncoding.EncodeToString([]byte("forwarded-ok")),
		}
		if err := conn.WriteJSON(resp); err != nil {
			t.Errorf("write response failed: %v", err)
		}
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/hello?x=1", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("public request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "forwarded-ok" {
		t.Fatalf("unexpected body: %s", string(body))
	}

	<-done
}

func TestPublicHTTPConcurrentLimitPerSession(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.maxConcurrentReq = 1

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	firstReqSeen := make(chan tunnelMessage, 1)
	releaseFirst := make(chan struct{})
	sdkDone := make(chan struct{})
	go func() {
		defer close(sdkDone)
		var req tunnelMessage
		if err := conn.ReadJSON(&req); err != nil {
			t.Errorf("read first forwarded request failed: %v", err)
			return
		}
		firstReqSeen <- req
		<-releaseFirst
		resp := tunnelMessage{
			Type:      "response",
			RequestID: req.RequestID,
			Status:    http.StatusOK,
			Headers:   map[string][]string{"content-type": {"text/plain"}},
			BodyB64:   base64.StdEncoding.EncodeToString([]byte("ok-first")),
		}
		if err := conn.WriteJSON(resp); err != nil {
			t.Errorf("write first response failed: %v", err)
		}
	}()

	firstResult := make(chan *http.Response, 1)
	firstErr := make(chan error, 1)
	go func() {
		req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/slow", nil)
		req1.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
		resp, err := http.DefaultClient.Do(req1)
		firstErr <- err
		firstResult <- resp
	}()

	<-firstReqSeen

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/second", nil)
	req2.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 429 for concurrent limit, got %d body=%s", resp2.StatusCode, string(body))
	}

	close(releaseFirst)
	<-sdkDone

	if err := <-firstErr; err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	resp1 := <-firstResult
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected first request to complete with 200, got %d", resp1.StatusCode)
	}
}

func TestPublicWebSocketForwarding(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	sdkConn := dialSDKWS(t, ts.URL, session)
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
	if openMsg.Type != "ws_open" {
		t.Fatalf("expected ws_open, got %s", openMsg.Type)
	}
	connectionID := openMsg.ConnectionID

	if err := publicConn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("public ws write failed: %v", err)
	}

	_ = sdkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var dataMsg tunnelMessage
	if err := sdkConn.ReadJSON(&dataMsg); err != nil {
		t.Fatalf("read ws_data failed: %v", err)
	}
	if dataMsg.Type != "ws_data" {
		t.Fatalf("expected ws_data, got %s", dataMsg.Type)
	}
	if dataMsg.ConnectionID != connectionID {
		t.Fatalf("unexpected connection id: %s", dataMsg.ConnectionID)
	}
	payload, err := base64.StdEncoding.DecodeString(dataMsg.DataB64)
	if err != nil {
		t.Fatalf("decode ws_data failed: %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("unexpected payload: %s", string(payload))
	}

	echo := tunnelMessage{
		Type:         "ws_data",
		ConnectionID: connectionID,
		Opcode:       "text",
		DataB64:      base64.StdEncoding.EncodeToString([]byte("echo:hello")),
	}
	if err := sdkConn.WriteJSON(echo); err != nil {
		t.Fatalf("sdk ws write failed: %v", err)
	}

	_ = publicConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, resp, err := publicConn.ReadMessage()
	if err != nil {
		t.Fatalf("public ws read failed: %v", err)
	}
	if string(resp) != "echo:hello" {
		t.Fatalf("unexpected public ws response: %s", string(resp))
	}
}

func TestUnknownTunnelHost(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Host = "unknown.0x0f.me"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestRootDomainCurlServesJSON(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Host = s.rootDomain
	req.Header.Set("User-Agent", "curl/8.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected application/json content-type, got %s", ct)
	}
}

func TestRootDomainBrowserServesJSON(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Host = s.rootDomain
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected application/json content-type, got %s", ct)
	}
}

func createSessionWithFingerprint(t *testing.T, baseURL, fingerprint string, port int) createSessionResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"ttl_seconds": 0,
		"fingerprint": fingerprint,
		"port":        port,
	})
	resp, err := http.Post(baseURL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create session request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("create session status=%d body=%s", resp.StatusCode, string(respBody))
	}
	var out createSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode session response failed: %v", err)
	}
	return out
}

func TestFingerprintDeterministicSubdomain(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	fp := "abc123def456"
	s1 := createSessionWithFingerprint(t, ts.URL, fp, 3000)
	s2 := createSessionWithFingerprint(t, ts.URL, fp, 3000)

	if s1.Subdomain != s2.Subdomain {
		t.Fatalf("same fingerprint+port should yield same subdomain: %s vs %s", s1.Subdomain, s2.Subdomain)
	}
	if !strings.HasPrefix(s1.Subdomain, "dm-") {
		t.Fatalf("deterministic subdomain should have dm- prefix, got %s", s1.Subdomain)
	}
	if s1.SessionID == s2.SessionID {
		t.Fatal("session IDs should be different (old session replaced)")
	}
}

func TestFingerprintDifferentPortDifferentSubdomain(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	fp := "samemachine"
	s1 := createSessionWithFingerprint(t, ts.URL, fp, 3000)
	s2 := createSessionWithFingerprint(t, ts.URL, fp, 8080)

	if s1.Subdomain == s2.Subdomain {
		t.Fatalf("different ports should yield different subdomains: both got %s", s1.Subdomain)
	}
}

func TestFingerprintConflictDifferentClient(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	s1 := createSessionWithFingerprint(t, ts.URL, "client-a", 3000)

	body, _ := json.Marshal(map[string]any{
		"ttl_seconds": 0,
		"fingerprint": "client-b-crafted-to-collide",
		"port":        3000,
	})
	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	_ = s1
	if s1.Subdomain == deterministicSubdomain("client-b-crafted-to-collide", 3000) {
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("expected 409 for subdomain conflict with different fingerprint, got %d", resp.StatusCode)
		}
	}
}

func TestNoFingerprintFallbackRandom(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	s1 := createSession(t, ts.URL)
	s2 := createSession(t, ts.URL)

	if !strings.HasPrefix(s1.Subdomain, "qs-") {
		t.Fatalf("no-fingerprint subdomain should have qs- prefix, got %s", s1.Subdomain)
	}
	if s1.Subdomain == s2.Subdomain {
		t.Fatalf("random subdomains should differ: both got %s", s1.Subdomain)
	}
}

func TestWSEndpointDoesNotContainToken(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	if strings.Contains(session.WSEndpoint, "token=") {
		t.Fatalf("WSEndpoint should NOT contain token parameter: %s", session.WSEndpoint)
	}
	if !strings.Contains(session.WSEndpoint, "session_id=") {
		t.Fatalf("WSEndpoint should contain session_id: %s", session.WSEndpoint)
	}
}

func TestWSAuthTimeout(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/api/v1/tunnel/ws?session_id=" + session.SessionID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	_ = conn.WriteJSON(tunnelMessage{Type: "auth", Token: "wrong-token"})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var errMsg tunnelMessage
	if err := conn.ReadJSON(&errMsg); err != nil {
		t.Fatalf("expected error message, got read error: %v", err)
	}
	if errMsg.Type != "error" {
		t.Fatalf("expected error type, got %s", errMsg.Type)
	}
}
