package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/tunnel/ws?session_id="+session.SessionID+"&token="+session.Token, nil)
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
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
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

	sdkConn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
	sdkConn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}

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
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
	sdkConn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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

	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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

// --- X-Forwarded headers are set correctly ---

func TestPublicHTTPForwardedHeaders(t *testing.T) {
	s, ts := newTestServer()
	defer ts.Close()

	session := createSession(t, ts.URL)
	conn, _, err := websocket.DefaultDialer.Dial(session.WSEndpoint, nil)
	if err != nil {
		t.Fatalf("dial sdk ws failed: %v", err)
	}
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
