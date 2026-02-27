package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultAddr               = ":8080"
	defaultRootDomain         = "0x0f.me"
	defaultSessionTTL         = 2 * time.Hour
	defaultRequestTimeout     = 20 * time.Second
	defaultMaxSessionsPerIP   = 5
	defaultCreatePerMinute    = 20
	defaultMaxHTTPBodyBytes   = 8 * 1024 * 1024
	defaultMaxWSMessageBytes  = 8 * 1024 * 1024
	defaultCleanupIntervalSec = 30
)

type tunnelMessage struct {
	Type         string              `json:"type"`
	RequestID    string              `json:"request_id,omitempty"`
	ConnectionID string              `json:"connection_id,omitempty"`
	Method       string              `json:"method,omitempty"`
	Path         string              `json:"path,omitempty"`
	Query        string              `json:"query,omitempty"`
	Status       int                 `json:"status,omitempty"`
	Headers      map[string][]string `json:"headers,omitempty"`
	BodyB64      string              `json:"body_b64,omitempty"`
	DataB64      string              `json:"data_b64,omitempty"`
	Opcode       string              `json:"opcode,omitempty"`
	Code         int                 `json:"code,omitempty"`
	Reason       string              `json:"reason,omitempty"`
	ErrorCode    string              `json:"code_name,omitempty"`
	Message      string              `json:"message,omitempty"`
}

type createSessionRequest struct {
	TTLSeconds  int    `json:"ttl_seconds"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Port        int    `json:"port,omitempty"`
}

type createSessionResponse struct {
	SessionID  string `json:"session_id"`
	Subdomain  string `json:"subdomain"`
	PublicURL  string `json:"public_url"`
	WSEndpoint string `json:"ws_endpoint"`
	Token      string `json:"token"`
	TTLSeconds int    `json:"ttl_seconds"`
	ExpiresAt  string `json:"expires_at"`
}

type heartbeatResponse struct {
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
}

type apiError struct {
	Error string `json:"error"`
}

type bridgeConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (b *bridgeConn) writeMessage(messageType int, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn.WriteMessage(messageType, payload)
}

type tunnelSession struct {
	id          string
	token       string
	subdomain   string
	clientIP    string
	fingerprint string
	expiresAt   time.Time

	conn   *websocket.Conn
	connMu sync.RWMutex
	writeM sync.Mutex

	pending   map[string]chan tunnelMessage
	pendingMu sync.Mutex

	wsConns   map[string]*bridgeConn
	wsConnsMu sync.Mutex
}

func (s *tunnelSession) isExpired(now time.Time) bool {
	return now.After(s.expiresAt)
}

func (s *tunnelSession) setConn(conn *websocket.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.conn = conn
}

func (s *tunnelSession) clearConn() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.conn = nil
}

func (s *tunnelSession) getConn() *websocket.Conn {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return s.conn
}

func (s *tunnelSession) send(msg tunnelMessage) error {
	s.writeM.Lock()
	defer s.writeM.Unlock()
	s.connMu.RLock()
	conn := s.conn
	s.connMu.RUnlock()
	if conn == nil {
		return errors.New("sdk websocket not connected")
	}
	return conn.WriteJSON(msg)
}

func (s *tunnelSession) addPending(requestID string, ch chan tunnelMessage) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.pending[requestID] = ch
}

func (s *tunnelSession) popPending(requestID string) chan tunnelMessage {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	ch := s.pending[requestID]
	delete(s.pending, requestID)
	return ch
}

func (s *tunnelSession) registerBridge(connectionID string, conn *websocket.Conn) {
	s.wsConnsMu.Lock()
	defer s.wsConnsMu.Unlock()
	s.wsConns[connectionID] = &bridgeConn{conn: conn}
}

func (s *tunnelSession) popBridge(connectionID string) *bridgeConn {
	s.wsConnsMu.Lock()
	defer s.wsConnsMu.Unlock()
	conn := s.wsConns[connectionID]
	delete(s.wsConns, connectionID)
	return conn
}

func (s *tunnelSession) getBridge(connectionID string) *bridgeConn {
	s.wsConnsMu.Lock()
	defer s.wsConnsMu.Unlock()
	return s.wsConns[connectionID]
}

func (s *tunnelSession) closeAllBridgeConns() {
	s.wsConnsMu.Lock()
	defer s.wsConnsMu.Unlock()
	for id, conn := range s.wsConns {
		_ = conn.conn.Close()
		delete(s.wsConns, id)
	}
}

func (s *tunnelSession) failAllPending(msg tunnelMessage) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for id, ch := range s.pending {
		ch <- msg
		close(ch)
		delete(s.pending, id)
	}
}

type createWindow struct {
	start time.Time
	count int
}

type server struct {
	addr             string
	rootDomain       string
	sessionTTL       time.Duration
	requestTimeout   time.Duration
	maxSessionsPerIP int
	createPerMinute  int
	maxHTTPBodyBytes int64
	maxWSMessageSize int64

	allowIPs map[string]struct{}
	denyIPs  map[string]struct{}

	mu           sync.RWMutex
	sessions     map[string]*tunnelSession
	bySubdomain  map[string]string
	ipSessionNum map[string]int
	ipCreates    map[string]*createWindow
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool { return true },
}

func main() {
	s := newServerFromEnv()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/healthz", s.handleHealthz)
	mux.HandleFunc("/api/v1/sessions", s.handleCreateSession)
	mux.HandleFunc("/api/v1/sessions/", s.handleSessionAction)
	mux.HandleFunc("/api/v1/tunnel/ws", s.handleTunnelWS)
	mux.HandleFunc("/", s.handlePublicRequest)

	go s.cleanupExpiredLoop()

	log.Printf("demoit gateway listening on %s with root domain %s", s.addr, s.rootDomain)
	if err := http.ListenAndServe(s.addr, s.withLogging(mux)); err != nil {
		log.Fatalf("listen failed: %v", err)
	}
}

func newServerFromEnv() *server {
	ttlSeconds := envInt("DEMOIT_SESSION_TTL_SECONDS", int(defaultSessionTTL.Seconds()))
	requestTimeout := envInt("DEMOIT_REQUEST_TIMEOUT_SECONDS", int(defaultRequestTimeout.Seconds()))

	return &server{
		addr:             envString("DEMOIT_ADDR", defaultAddr),
		rootDomain:       envString("DEMOIT_ROOT_DOMAIN", defaultRootDomain),
		sessionTTL:       time.Duration(ttlSeconds) * time.Second,
		requestTimeout:   time.Duration(requestTimeout) * time.Second,
		maxSessionsPerIP: envInt("DEMOIT_MAX_SESSIONS_PER_IP", defaultMaxSessionsPerIP),
		createPerMinute:  envInt("DEMOIT_MAX_CREATE_PER_MINUTE", defaultCreatePerMinute),
		maxHTTPBodyBytes: int64(envInt("DEMOIT_MAX_HTTP_BODY_BYTES", defaultMaxHTTPBodyBytes)),
		maxWSMessageSize: int64(envInt("DEMOIT_MAX_WS_MESSAGE_BYTES", defaultMaxWSMessageBytes)),
		allowIPs:         listToSet(envString("DEMOIT_ALLOW_IPS", "")),
		denyIPs:          listToSet(envString("DEMOIT_DENY_IPS", "")),
		sessions:         make(map[string]*tunnelSession),
		bySubdomain:      make(map[string]string),
		ipSessionNum:     make(map[string]int),
		ipCreates:        make(map[string]*createWindow),
	}
}

func (s *server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s host=%s remote=%s took=%s", r.Method, r.URL.Path, r.Host, remoteIP(r), time.Since(start))
	})
}

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
		return
	}

	ip := remoteIP(r)
	if !s.ipAllowed(ip) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "ip blocked"})
		return
	}
	if !s.allowCreate(ip) {
		writeJSON(w, http.StatusTooManyRequests, apiError{Error: "create session rate limited"})
		return
	}

	var req createSessionRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
			return
		}
	}

	ttl := s.sessionTTL
	if req.TTLSeconds > 0 && req.TTLSeconds < int(s.sessionTTL.Seconds()) {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ipSessionNum[ip] >= s.maxSessionsPerIP {
		writeJSON(w, http.StatusTooManyRequests, apiError{Error: "max sessions reached for this ip"})
		return
	}

	subdomain := "qs-" + randHex(4)
	fingerprint := req.Fingerprint

	if fingerprint != "" && req.Port > 0 {
		subdomain = deterministicSubdomain(fingerprint, req.Port)
		if existingSessionID, occupied := s.bySubdomain[subdomain]; occupied {
			existing := s.sessions[existingSessionID]
			if existing != nil && existing.fingerprint == fingerprint {
				s.removeSessionLocked(existingSessionID, existing)
			} else if existing != nil {
				writeJSON(w, http.StatusConflict, apiError{Error: "subdomain in use by another client"})
				return
			}
		}
	}

	sessionID := "ses_" + randHex(8)
	token := randHex(16)

	exp := time.Now().Add(ttl)
	session := &tunnelSession{
		id:          sessionID,
		token:       token,
		subdomain:   subdomain,
		clientIP:    ip,
		fingerprint: fingerprint,
		expiresAt:   exp,
		pending:     make(map[string]chan tunnelMessage),
		wsConns:     make(map[string]*bridgeConn),
	}
	s.sessions[sessionID] = session
	s.bySubdomain[subdomain] = sessionID
	s.ipSessionNum[ip]++

	wsEndpoint := buildWSEndpoint(r, sessionID, token)
	publicURL := buildPublicURL(r, subdomain, s.rootDomain)
	writeJSON(w, http.StatusCreated, createSessionResponse{
		SessionID:  sessionID,
		Subdomain:  subdomain,
		PublicURL:  publicURL,
		WSEndpoint: wsEndpoint,
		Token:      token,
		TTLSeconds: int(ttl.Seconds()),
		ExpiresAt:  exp.UTC().Format(time.RFC3339),
	})
}

func (s *server) handleSessionAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/")
	path = strings.Trim(path, "/")
	if path == "" {
		writeJSON(w, http.StatusNotFound, apiError{Error: "missing session id"})
		return
	}

	parts := strings.Split(path, "/")
	sessionID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch r.Method {
	case http.MethodPost:
		if action != "heartbeat" {
			writeJSON(w, http.StatusNotFound, apiError{Error: "unsupported action"})
			return
		}
		s.handleHeartbeat(w, r, sessionID)
	case http.MethodDelete:
		if action != "" {
			writeJSON(w, http.StatusNotFound, apiError{Error: "unsupported action"})
			return
		}
		s.handleDeleteSession(w, r, sessionID)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
	}
}

func (s *server) handleHeartbeat(w http.ResponseWriter, r *http.Request, sessionID string) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		writeJSON(w, http.StatusNotFound, apiError{Error: "session not found"})
		return
	}
	if token != session.token {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid token"})
		return
	}
	session.expiresAt = time.Now().Add(s.sessionTTL)
	writeJSON(w, http.StatusOK, heartbeatResponse{
		SessionID: sessionID,
		ExpiresAt: session.expiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *server) handleDeleteSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		writeJSON(w, http.StatusNotFound, apiError{Error: "session not found"})
		return
	}
	if token != session.token {
		s.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid token"})
		return
	}
	delete(s.sessions, sessionID)
	delete(s.bySubdomain, session.subdomain)
	s.ipSessionNum[session.clientIP]--
	s.mu.Unlock()

	conn := session.getConn()
	if conn != nil {
		_ = conn.Close()
	}
	session.closeAllBridgeConns()
	session.failAllPending(tunnelMessage{Type: "error", Message: "session closed"})

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *server) handleTunnelWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiError{Error: "method not allowed"})
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	token := r.URL.Query().Get("token")
	if sessionID == "" || token == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "session_id and token required"})
		return
	}

	s.mu.RLock()
	session, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, apiError{Error: "session not found"})
		return
	}
	if token != session.token {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid token"})
		return
	}
	if session.isExpired(time.Now()) {
		writeJSON(w, http.StatusGone, apiError{Error: "session expired"})
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade sdk ws failed: %v", err)
		return
	}
	conn.SetReadLimit(s.maxWSMessageSize)

	prev := session.getConn()
	if prev != nil {
		_ = prev.Close()
	}
	session.setConn(conn)

	go s.readSDKMessages(session)
}

func (s *server) readSDKMessages(session *tunnelSession) {
	conn := session.getConn()
	if conn == nil {
		return
	}
	defer func() {
		_ = conn.Close()
		session.clearConn()
		session.closeAllBridgeConns()
		session.failAllPending(tunnelMessage{Type: "error", Message: "sdk disconnected"})
	}()

	for {
		var msg tunnelMessage
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("read sdk message failed session=%s err=%v", session.id, err)
			return
		}
		switch msg.Type {
		case "pong":
			continue
		case "ping":
			_ = session.send(tunnelMessage{Type: "pong"})
		case "response":
			ch := session.popPending(msg.RequestID)
			if ch != nil {
				ch <- msg
				close(ch)
			}
		case "ws_data":
			bridge := session.getBridge(msg.ConnectionID)
			if bridge == nil {
				continue
			}
			payload, err := base64.StdEncoding.DecodeString(msg.DataB64)
			if err != nil {
				continue
			}
			messageType := websocket.TextMessage
			if msg.Opcode == "binary" {
				messageType = websocket.BinaryMessage
			}
			_ = bridge.writeMessage(messageType, payload)
		case "ws_close":
			bridge := session.popBridge(msg.ConnectionID)
			if bridge != nil {
				_ = bridge.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(msg.Code, msg.Reason), time.Now().Add(2*time.Second))
				_ = bridge.conn.Close()
			}
		case "error":
			log.Printf("sdk error session=%s req=%s msg=%s", session.id, msg.RequestID, msg.Message)
		}
	}
}

func (s *server) handlePublicRequest(w http.ResponseWriter, r *http.Request) {
	host := hostWithoutPort(r.Host)
	if host == s.rootDomain {
		writeJSON(w, http.StatusOK, map[string]any{
			"service":     "demoit-gateway",
			"root_domain": s.rootDomain,
			"docs":        "/docs/protocol-v1.md",
		})
		return
	}

	session := s.findSessionByHost(host)
	if session == nil {
		writeJSON(w, http.StatusNotFound, apiError{Error: "unknown tunnel subdomain"})
		return
	}
	if session.isExpired(time.Now()) {
		writeJSON(w, http.StatusGone, apiError{Error: "session expired"})
		return
	}
	if session.getConn() == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "tunnel disconnected"})
		return
	}

	if websocket.IsWebSocketUpgrade(r) {
		s.handlePublicWebSocket(w, r, session)
		return
	}
	s.handlePublicHTTP(w, r, session)
}

func (s *server) handlePublicHTTP(w http.ResponseWriter, r *http.Request, session *tunnelSession) {
	start := time.Now()
	body, err := readRequestBody(r, s.maxHTTPBodyBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	reqID := "req_" + randHex(8)
	responseCh := make(chan tunnelMessage, 1)
	session.addPending(reqID, responseCh)

	msg := tunnelMessage{
		Type:      "request",
		RequestID: reqID,
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Headers:   cloneHeader(r.Header),
		BodyB64:   base64.StdEncoding.EncodeToString(body),
	}
	msg.Headers["x-forwarded-host"] = []string{r.Host}
	msg.Headers["x-forwarded-proto"] = []string{requestProto(r)}
	msg.Headers["x-forwarded-for"] = []string{remoteIP(r)}
	log.Printf(
		"tunnel request session=%s req=%s method=%s path=%s query=%s body_bytes=%d host=%s",
		session.id,
		reqID,
		r.Method,
		r.URL.Path,
		r.URL.RawQuery,
		len(body),
		r.Host,
	)

	if err := session.send(msg); err != nil {
		_ = session.popPending(reqID)
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "failed to forward request"})
		return
	}

	select {
	case response := <-responseCh:
		if response.Type == "error" {
			log.Printf(
				"tunnel response session=%s req=%s status=%d error=%s took=%s",
				session.id,
				reqID,
				http.StatusBadGateway,
				response.Message,
				time.Since(start),
			)
			writeJSON(w, http.StatusBadGateway, apiError{Error: response.Message})
			return
		}
		responseBody, err := base64.StdEncoding.DecodeString(response.BodyB64)
		if err != nil {
			log.Printf(
				"tunnel response session=%s req=%s status=%d error=invalid response payload took=%s",
				session.id,
				reqID,
				http.StatusBadGateway,
				time.Since(start),
			)
			writeJSON(w, http.StatusBadGateway, apiError{Error: "invalid response payload"})
			return
		}
		log.Printf(
			"tunnel response session=%s req=%s status=%d body_bytes=%d took=%s",
			session.id,
			reqID,
			response.Status,
			len(responseBody),
			time.Since(start),
		)
		writeForwardedResponse(w, response.Status, response.Headers, responseBody)
	case <-time.After(s.requestTimeout):
		_ = session.popPending(reqID)
		log.Printf(
			"tunnel response session=%s req=%s status=%d error=timeout took=%s",
			session.id,
			reqID,
			http.StatusGatewayTimeout,
			time.Since(start),
		)
		writeJSON(w, http.StatusGatewayTimeout, apiError{Error: "tunnel response timeout"})
	}
}

func (s *server) handlePublicWebSocket(w http.ResponseWriter, r *http.Request, session *tunnelSession) {
	publicConn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade public ws failed: %v", err)
		return
	}
	publicConn.SetReadLimit(s.maxWSMessageSize)
	defer func() { _ = publicConn.Close() }()

	connectionID := "ws_" + randHex(8)
	session.registerBridge(connectionID, publicConn)
	defer session.popBridge(connectionID)

	openMsg := tunnelMessage{
		Type:         "ws_open",
		ConnectionID: connectionID,
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		Headers:      cloneHeader(r.Header),
	}
	if err := session.send(openMsg); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			messageType, payload, err := publicConn.ReadMessage()
			if err != nil {
				_ = session.send(tunnelMessage{
					Type:         "ws_close",
					ConnectionID: connectionID,
					Code:         websocket.CloseNormalClosure,
					Reason:       "public websocket closed",
				})
				return
			}
			opcode := "text"
			if messageType == websocket.BinaryMessage {
				opcode = "binary"
			}
			_ = session.send(tunnelMessage{
				Type:         "ws_data",
				ConnectionID: connectionID,
				Opcode:       opcode,
				DataB64:      base64.StdEncoding.EncodeToString(payload),
			})
		}
	}()

	<-done
}

func (s *server) cleanupExpiredLoop() {
	t := time.NewTicker(defaultCleanupIntervalSec * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		expired := make([]*tunnelSession, 0)

		s.mu.Lock()
		for id, session := range s.sessions {
			if !session.isExpired(now) {
				continue
			}
			delete(s.sessions, id)
			delete(s.bySubdomain, session.subdomain)
			s.ipSessionNum[session.clientIP]--
			expired = append(expired, session)
		}
		s.mu.Unlock()

		for _, session := range expired {
			if conn := session.getConn(); conn != nil {
				_ = conn.Close()
			}
			session.closeAllBridgeConns()
			session.failAllPending(tunnelMessage{Type: "error", Message: "session expired"})
		}
	}
}

func (s *server) findSessionByHost(host string) *tunnelSession {
	if !strings.HasSuffix(host, "."+s.rootDomain) {
		return nil
	}
	subdomain := strings.TrimSuffix(host, "."+s.rootDomain)
	if subdomain == "" {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	sessionID := s.bySubdomain[subdomain]
	return s.sessions[sessionID]
}

func (s *server) ipAllowed(ip string) bool {
	if len(s.allowIPs) > 0 {
		if _, ok := s.allowIPs[ip]; !ok {
			return false
		}
	}
	if _, denied := s.denyIPs[ip]; denied {
		return false
	}
	return true
}

func (s *server) allowCreate(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	window, ok := s.ipCreates[ip]
	if !ok || time.Since(window.start) > time.Minute {
		s.ipCreates[ip] = &createWindow{
			start: time.Now(),
			count: 1,
		}
		return true
	}
	if window.count >= s.createPerMinute {
		return false
	}
	window.count++
	return true
}

func deterministicSubdomain(fingerprint string, port int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", fingerprint, port)))
	return "dm-" + hex.EncodeToString(h[:4])
}

func (s *server) removeSessionLocked(sessionID string, session *tunnelSession) {
	delete(s.sessions, sessionID)
	delete(s.bySubdomain, session.subdomain)
	s.ipSessionNum[session.clientIP]--
	if conn := session.getConn(); conn != nil {
		_ = conn.Close()
	}
	go func() {
		session.closeAllBridgeConns()
		session.failAllPending(tunnelMessage{Type: "error", Message: "session replaced"})
	}()
}

func buildWSEndpoint(r *http.Request, sessionID, token string) string {
	scheme := "ws"
	if requestProto(r) == "https" {
		scheme = "wss"
	}
	host := r.Host
	return fmt.Sprintf("%s://%s/api/v1/tunnel/ws?session_id=%s&token=%s", scheme, host, sessionID, token)
}

func buildPublicURL(r *http.Request, subdomain, rootDomain string) string {
	scheme := requestProto(r)
	return fmt.Sprintf("%s://%s.%s", scheme, subdomain, rootDomain)
}

func requestProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		return strings.ToLower(strings.TrimSpace(forwarded))
	}
	return "http"
}

func readRequestBody(r *http.Request, maxBytes int64) ([]byte, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, errors.New("failed to read request body")
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("request body too large")
	}
	return body, nil
}

func writeForwardedResponse(w http.ResponseWriter, status int, headers map[string][]string, body []byte) {
	for k, vv := range headers {
		lk := strings.ToLower(k)
		if lk == "connection" || lk == "upgrade" || lk == "transfer-encoding" {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func cloneHeader(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vv := range h {
		cp := make([]string, len(vv))
		copy(cp, vv)
		out[strings.ToLower(k)] = cp
	}
	return out
}

func hostWithoutPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func envString(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func listToSet(v string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out[item] = struct{}{}
	}
	return out
}
