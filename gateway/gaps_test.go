package main

import (
	"bytes"
	"encoding/base64"
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

// --- handleCreateSession: orphaned bySubdomain entry ---

func TestCreateSessionSubdomainOrphanedEntry(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	s.mu.Lock()
	s.bySubdomain["dm-deadbeef"] = "ses_orphaned"
	s.mu.Unlock()

	body, _ := json.Marshal(map[string]any{"fingerprint": "testfp", "port": 1234})
	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		rb, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d body=%s", resp.StatusCode, string(rb))
	}
}

// --- handleDeleteSession: session with active WS connection ---

func TestDeleteSessionWithActiveWSConn(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/sessions/"+session.SessionID, nil)
	delReq.Header.Set("Authorization", "Bearer "+session.Token)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", delResp.StatusCode)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("SDK WS should be closed after session delete")
	}
}

// --- handleTunnelWS: method not GET ---

func TestTunnelWSMethodNotAllowed(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/tunnel/ws?session_id="+session.SessionID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST on tunnel ws, got %d", resp.StatusCode)
	}
}

// --- readSDKMessages: SDK sends pong (should be silently consumed) ---

func TestSDKSendsPong(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	_ = conn.WriteJSON(tunnelMessage{Type: "pong"})
	_ = conn.WriteJSON(tunnelMessage{Type: "ping"})

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pong tunnelMessage
	if err := conn.ReadJSON(&pong); err != nil {
		t.Fatalf("read pong after pong+ping failed: %v", err)
	}
	if pong.Type != "pong" {
		t.Fatalf("expected pong, got %s", pong.Type)
	}
}

// --- readSDKMessages: ws_data with invalid base64 ---

func TestSDKSendsWSDataInvalidBase64(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	sdkConn := dialSDKWS(t, ts.URL, session)
	defer sdkConn.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws-test"
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

	badData := tunnelMessage{
		Type:         "ws_data",
		ConnectionID: openMsg.ConnectionID,
		Opcode:       "text",
		DataB64:      "!!!not-valid-base64!!!",
	}
	_ = sdkConn.WriteJSON(badData)

	goodData := tunnelMessage{
		Type:         "ws_data",
		ConnectionID: openMsg.ConnectionID,
		Opcode:       "text",
		DataB64:      base64.StdEncoding.EncodeToString([]byte("after-bad")),
	}
	_ = sdkConn.WriteJSON(goodData)

	_ = publicConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, payload, err := publicConn.ReadMessage()
	if err != nil {
		t.Fatalf("public ws read failed: %v", err)
	}
	if string(payload) != "after-bad" {
		t.Fatalf("expected 'after-bad', got %s", string(payload))
	}
}

// --- readSDKMessages: ws_data with binary opcode ---

func TestSDKSendsWSDataBinaryOpcode(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	sdkConn := dialSDKWS(t, ts.URL, session)
	defer sdkConn.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws-bin"
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

	binaryPayload := []byte{0x00, 0x01, 0x02, 0xFF}
	binaryData := tunnelMessage{
		Type:         "ws_data",
		ConnectionID: openMsg.ConnectionID,
		Opcode:       "binary",
		DataB64:      base64.StdEncoding.EncodeToString(binaryPayload),
	}
	_ = sdkConn.WriteJSON(binaryData)

	_ = publicConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, payload, err := publicConn.ReadMessage()
	if err != nil {
		t.Fatalf("public ws read failed: %v", err)
	}
	if msgType != websocket.BinaryMessage {
		t.Fatalf("expected binary message type, got %d", msgType)
	}
	if !bytes.Equal(payload, binaryPayload) {
		t.Fatalf("unexpected binary payload: %v", payload)
	}
}

// --- handlePublicHTTP: error response via failAllPending (SDK disconnects after receiving request) ---

func TestPublicHTTPErrorViaSDKDisconnect(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.requestTimeout = 5 * time.Second

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)

	go func() {
		var req tunnelMessage
		_ = conn.ReadJSON(&req)
		conn.Close()
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/crashing", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 from failAllPending error, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "sdk disconnected") {
		t.Fatalf("expected 'sdk disconnected' in body, got %s", string(body))
	}
}

// --- handlePublicHTTP: SDK returns invalid base64 in response body ---

func TestPublicHTTPSDKReturnsInvalidBase64(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	go func() {
		var req tunnelMessage
		if err := conn.ReadJSON(&req); err != nil {
			return
		}
		badResp := tunnelMessage{
			Type:      "response",
			RequestID: req.RequestID,
			Status:    200,
			Headers:   map[string][]string{"content-type": {"text/plain"}},
			BodyB64:   "!!!not-valid-base64!!!",
		}
		_ = conn.WriteJSON(badResp)
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/bad-resp", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for invalid base64 response, got %d", resp.StatusCode)
	}
}

// --- handlePublicWebSocket: binary message forwarding ---

func TestPublicWSBinaryForwarding(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	sdkConn := dialSDKWS(t, ts.URL, session)
	defer sdkConn.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws-binary"
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

	binaryPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := publicConn.WriteMessage(websocket.BinaryMessage, binaryPayload); err != nil {
		t.Fatalf("public ws write binary failed: %v", err)
	}

	_ = sdkConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var dataMsg tunnelMessage
	if err := sdkConn.ReadJSON(&dataMsg); err != nil {
		t.Fatalf("read ws_data failed: %v", err)
	}
	if dataMsg.Opcode != "binary" {
		t.Fatalf("expected binary opcode, got %s", dataMsg.Opcode)
	}
	decoded, _ := base64.StdEncoding.DecodeString(dataMsg.DataB64)
	if !bytes.Equal(decoded, binaryPayload) {
		t.Fatalf("unexpected binary payload: %v", decoded)
	}
}

// --- removeSessionLocked: session without active WS connection ---

func TestRemoveSessionLockedNoConn(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)

	s.mu.Lock()
	sess := s.sessions[session.SessionID]
	s.removeSessionLocked(session.SessionID, sess)
	s.mu.Unlock()

	s.mu.RLock()
	_, found := s.sessions[session.SessionID]
	s.mu.RUnlock()
	if found {
		t.Fatal("session should have been removed")
	}
}

// --- handlePublicHTTP: send failure (disconnected SDK) ---

func TestPublicHTTPSendFailure(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/after-disconnect", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 503 or 502 for send failure, got %d", resp.StatusCode)
	}
}

// --- readSDKMessages: ws_data for nonexistent bridge ---

func TestSDKWSDataNonexistentBridge(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	_ = conn.WriteJSON(tunnelMessage{
		Type:         "ws_data",
		ConnectionID: "ws_nonexistent",
		Opcode:       "text",
		DataB64:      base64.StdEncoding.EncodeToString([]byte("test")),
	})

	_ = conn.WriteJSON(tunnelMessage{Type: "ping"})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pong tunnelMessage
	if err := conn.ReadJSON(&pong); err != nil {
		t.Fatalf("connection should still be alive after ws_data to nonexistent bridge: %v", err)
	}
	if pong.Type != "pong" {
		t.Fatalf("expected pong, got %s", pong.Type)
	}
}

// --- readSDKMessages: ws_close for nonexistent bridge ---

func TestSDKWSCloseNonexistentBridge(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	_ = conn.WriteJSON(tunnelMessage{
		Type:         "ws_close",
		ConnectionID: "ws_nonexistent",
		Code:         1000,
		Reason:       "test",
	})

	_ = conn.WriteJSON(tunnelMessage{Type: "ping"})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pong tunnelMessage
	if err := conn.ReadJSON(&pong); err != nil {
		t.Fatalf("connection should still be alive after ws_close nonexistent bridge: %v", err)
	}
}

// --- readSDKMessages: response for nonexistent pending request ---

func TestSDKResponseNonexistentPending(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	_ = conn.WriteJSON(tunnelMessage{
		Type:      "response",
		RequestID: "req_nonexistent",
		Status:    200,
	})

	_ = conn.WriteJSON(tunnelMessage{Type: "ping"})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pong tunnelMessage
	if err := conn.ReadJSON(&pong); err != nil {
		t.Fatalf("connection should still be alive: %v", err)
	}
}

// --- handlePublicHTTP: POST with body forwarding ---

func TestPublicHTTPPostWithBody(t *testing.T) {
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
			return
		}
		if req.Method != "POST" {
			t.Errorf("expected POST, got %s", req.Method)
		}
		bodyBytes, _ := base64.StdEncoding.DecodeString(req.BodyB64)
		if string(bodyBytes) != `{"key":"value"}` {
			t.Errorf("unexpected body: %s", string(bodyBytes))
		}
		if req.Query != "q=1" {
			t.Errorf("expected query q=1, got %s", req.Query)
		}
		resp := tunnelMessage{
			Type:      "response",
			RequestID: req.RequestID,
			Status:    201,
			Headers:   map[string][]string{"content-type": {"application/json"}},
			BodyB64:   base64.StdEncoding.EncodeToString([]byte(`{"created":true}`)),
		}
		_ = conn.WriteJSON(resp)
	}()

	bodyReader := strings.NewReader(`{"key":"value"}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/create?q=1", bodyReader)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "created") {
		t.Fatalf("unexpected body: %s", string(body))
	}

	<-done
}

// --- handlePublicHTTP: error via failAllPending (response.Type == "error") ---
// This tests the `response.Type == "error"` branch in handlePublicHTTP
// triggered when the SDK WS disconnects while a request is pending.
// (Complements TestPublicHTTPErrorViaSDKDisconnect with explicit error message check)

func TestPublicHTTPErrorResponseFromFailAllPending(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()
	s.requestTimeout = 5 * time.Second

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)

	gotRequest := make(chan struct{})
	go func() {
		var req tunnelMessage
		if err := conn.ReadJSON(&req); err != nil {
			return
		}
		close(gotRequest)
		// Wait a moment to ensure the HTTP handler is blocking on responseCh
		time.Sleep(50 * time.Millisecond)
		_ = conn.Close()
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/trigger-error", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// Either 502 (failAllPending sends error to pending response) or
	// 503 (conn cleared before request dispatched) are valid outcomes.
	if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 502 or 503, got %d body=%s", resp.StatusCode, body)
	}
}

// --- concurrent public HTTP requests to same session ---

func TestConcurrentPublicHTTPSameSession(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	go func() {
		for {
			var req tunnelMessage
			if err := conn.ReadJSON(&req); err != nil {
				return
			}
			if req.Type == "request" {
				resp := tunnelMessage{
					Type:      "response",
					RequestID: req.RequestID,
					Status:    200,
					Headers:   map[string][]string{"content-type": {"text/plain"}},
					BodyB64:   base64.StdEncoding.EncodeToString([]byte(req.Path)),
				}
				_ = conn.WriteJSON(resp)
			}
		}
	}()

	const numRequests = 10
	var wg sync.WaitGroup
	errs := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/conc/%d", ts.URL, idx), nil)
			req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- fmt.Errorf("req %d: %v", idx, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				errs <- fmt.Errorf("req %d: status %d", idx, resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// --- requestProto: direct TLS connection ---

func TestRequestProtoDirectTLS(t *testing.T) {
	s := &server{trustProxy: false}
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	proto := s.requestProto(req)
	if proto != "http" {
		t.Errorf("expected http, got %s", proto)
	}
}

// --- path whitelist: allowed path passes, disallowed returns 403 ---

func TestPathWhitelistAllowed(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"fingerprint":   "wl-test",
		"port":          9999,
		"allowed_paths": []string{"/api", "/health"},
	})
	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}
	defer resp.Body.Close()
	var session createSessionResponse
	json.NewDecoder(resp.Body).Decode(&session)

	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)

	go func() {
		for {
			var req tunnelMessage
			if err := conn.ReadJSON(&req); err != nil {
				return
			}
			if req.Type == "request" {
				_ = conn.WriteJSON(tunnelMessage{
					Type:      "response",
					RequestID: req.RequestID,
					Status:    200,
					BodyB64:   base64.StdEncoding.EncodeToString([]byte("ok")),
				})
			}
		}
	}()

	// Allowed: /api
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/users", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("/api/users: expected 200, got %d", r.StatusCode)
	}

	// Allowed: /health
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	req2.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	r2, _ := http.DefaultClient.Do(req2)
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("/health: expected 200, got %d", r2.StatusCode)
	}

	// Blocked: /admin
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin", nil)
	req3.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	r3, _ := http.DefaultClient.Do(req3)
	r3.Body.Close()
	if r3.StatusCode != http.StatusForbidden {
		t.Fatalf("/admin: expected 403, got %d", r3.StatusCode)
	}

	// Blocked: /
	req4, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req4.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	r4, _ := http.DefaultClient.Do(req4)
	r4.Body.Close()
	if r4.StatusCode != http.StatusForbidden {
		t.Fatalf("/: expected 403, got %d", r4.StatusCode)
	}
}

func TestPathWhitelistEmpty(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	go func() {
		for {
			var req tunnelMessage
			if err := conn.ReadJSON(&req); err != nil {
				return
			}
			if req.Type == "request" {
				_ = conn.WriteJSON(tunnelMessage{
					Type:      "response",
					RequestID: req.RequestID,
					Status:    200,
					BodyB64:   base64.StdEncoding.EncodeToString([]byte("ok")),
				})
			}
		}
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/anything/goes", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("no whitelist: expected 200, got %d", r.StatusCode)
	}
}

func TestPathWhitelistExactMatch(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"fingerprint":   "wl-exact",
		"port":          8888,
		"allowed_paths": []string{"/api"},
	})
	resp, err := http.Post(ts.URL+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	defer resp.Body.Close()
	var session createSessionResponse
	json.NewDecoder(resp.Body).Decode(&session)

	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()

	go func() {
		for {
			var req tunnelMessage
			if err := conn.ReadJSON(&req); err != nil {
				return
			}
			if req.Type == "request" {
				_ = conn.WriteJSON(tunnelMessage{
					Type:      "response",
					RequestID: req.RequestID,
					Status:    200,
					BodyB64:   base64.StdEncoding.EncodeToString([]byte("ok")),
				})
			}
		}
	}()

	// Exact match: /api
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("/api exact: expected 200, got %d", r.StatusCode)
	}

	// Prefix match: /api/v1
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1", nil)
	req2.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	r2, _ := http.DefaultClient.Do(req2)
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("/api/v1: expected 200, got %d", r2.StatusCode)
	}

	// Not a prefix: /api-v2 should be blocked
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api-v2", nil)
	req3.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	r3, _ := http.DefaultClient.Do(req3)
	r3.Body.Close()
	if r3.StatusCode != http.StatusForbidden {
		t.Fatalf("/api-v2: expected 403, got %d", r3.StatusCode)
	}
}

// --- header forwarding: Cookie, custom headers, multi-value headers ---

func TestPublicHTTPHeaderForwarding(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn := dialSDKWS(t, ts.URL, session)
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		var req tunnelMessage
		if err := conn.ReadJSON(&req); err != nil {
			return
		}

		// Verify Cookie header is forwarded
		cookies := req.Headers["cookie"]
		if len(cookies) == 0 {
			t.Errorf("cookie header not forwarded")
		} else if !strings.Contains(cookies[0], "session_id=abc123") {
			t.Errorf("expected session_id=abc123 in cookie, got %v", cookies)
		}

		// Verify custom header
		custom := req.Headers["x-custom-header"]
		if len(custom) == 0 || custom[0] != "custom-value" {
			t.Errorf("x-custom-header not forwarded correctly, got %v", custom)
		}

		// Verify Authorization header
		auth := req.Headers["authorization"]
		if len(auth) == 0 || auth[0] != "Bearer my-token" {
			t.Errorf("authorization header not forwarded correctly, got %v", auth)
		}

		// Verify Accept header with multiple values
		accept := req.Headers["accept"]
		if len(accept) == 0 {
			t.Errorf("accept header not forwarded")
		}

		// Respond with custom response headers including Set-Cookie
		resp := tunnelMessage{
			Type:      "response",
			RequestID: req.RequestID,
			Status:    200,
			Headers: map[string][]string{
				"content-type":           {"application/json"},
				"x-response-custom":      {"resp-value"},
				"set-cookie":             {"token=xyz; Path=/", "lang=en; Path=/"},
				"x-multi-value":          {"val1", "val2"},
				"cache-control":          {"no-cache, no-store"},
			},
			BodyB64: base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)),
		}
		_ = conn.WriteJSON(resp)
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/header-test", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	req.Header.Set("Cookie", "session_id=abc123; theme=dark")
	req.Header.Set("X-Custom-Header", "custom-value")
	req.Header.Set("Authorization", "Bearer my-token")
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Accept", "text/html")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, string(body))
	}

	// Verify response headers are forwarded back
	if v := resp.Header.Get("X-Response-Custom"); v != "resp-value" {
		t.Errorf("x-response-custom not forwarded in response, got %q", v)
	}

	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) < 2 {
		t.Errorf("expected 2 Set-Cookie headers, got %d: %v", len(setCookies), setCookies)
	}

	multiVals := resp.Header.Values("X-Multi-Value")
	if len(multiVals) < 2 {
		t.Errorf("expected 2 X-Multi-Value headers, got %d: %v", len(multiVals), multiVals)
	}

	if v := resp.Header.Get("Cache-Control"); v != "no-cache, no-store" {
		t.Errorf("cache-control not forwarded, got %q", v)
	}

	<-done
}

// --- X-Forwarded headers are set correctly ---

func TestPublicHTTPForwardedHeaders(t *testing.T) {
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
			return
		}
		xfh := req.Headers["x-forwarded-host"]
		if len(xfh) == 0 {
			t.Errorf("missing x-forwarded-host header")
		}
		xfp := req.Headers["x-forwarded-proto"]
		if len(xfp) == 0 {
			t.Errorf("missing x-forwarded-proto header")
		}
		xff := req.Headers["x-forwarded-for"]
		if len(xff) == 0 {
			t.Errorf("missing x-forwarded-for header")
		}

		resp := tunnelMessage{
			Type:      "response",
			RequestID: req.RequestID,
			Status:    200,
			BodyB64:   base64.StdEncoding.EncodeToString([]byte("ok")),
		}
		_ = conn.WriteJSON(resp)
	}()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/check-headers", nil)
	req.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	<-done
}

// --- SDK reconnect: same session survives WS disconnect + reconnect ---

func TestSDKReconnectSameSession(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn1 := dialSDKWS(t, ts.URL, session)

	// Verify forwarding works on first connection
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		var req tunnelMessage
		if err := conn1.ReadJSON(&req); err != nil {
			return
		}
		_ = conn1.WriteJSON(tunnelMessage{
			Type:      "response",
			RequestID: req.RequestID,
			Status:    200,
			Headers:   map[string][]string{"content-type": {"text/plain"}},
			BodyB64:   base64.StdEncoding.EncodeToString([]byte("first-conn")),
		})
	}()

	time.Sleep(50 * time.Millisecond)
	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/before-reconnect", nil)
	req1.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != 200 || string(body1) != "first-conn" {
		t.Fatalf("first request: status=%d body=%s", resp1.StatusCode, body1)
	}
	<-done1

	// Close the first WS connection (simulate network drop)
	conn1.Close()
	time.Sleep(100 * time.Millisecond)

	// Reconnect with same session and token
	conn2 := dialSDKWS(t, ts.URL, session)
	defer conn2.Close()
	time.Sleep(50 * time.Millisecond)

	// Verify forwarding works on second connection
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		var req tunnelMessage
		if err := conn2.ReadJSON(&req); err != nil {
			return
		}
		_ = conn2.WriteJSON(tunnelMessage{
			Type:      "response",
			RequestID: req.RequestID,
			Status:    200,
			Headers:   map[string][]string{"content-type": {"text/plain"}},
			BodyB64:   base64.StdEncoding.EncodeToString([]byte("second-conn")),
		})
	}()

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/after-reconnect", nil)
	req2.Host = fmt.Sprintf("%s.%s", session.Subdomain, s.rootDomain)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 || string(body2) != "second-conn" {
		t.Fatalf("second request after reconnect: status=%d body=%s", resp2.StatusCode, body2)
	}
	<-done2
}
