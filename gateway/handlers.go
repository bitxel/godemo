package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func (s *server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s host=%s remote=%s took=%s", r.Method, r.URL.Path, r.Host, s.remoteIP(r), time.Since(start))
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

	ip := s.remoteIP(r)
	if !s.ipAllowed(ip) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "ip blocked"})
		return
	}
	if !s.allowCreate(ip) {
		writeJSON(w, http.StatusTooManyRequests, apiError{Error: "create session rate limited"})
		return
	}

	var req createSessionRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
			return
		}
	}

	if len(req.Fingerprint) > 256 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "fingerprint too long"})
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid port"})
		return
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

	subdomain := "qs-" + randHex(8)
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
	requestLimit := s.maxConcurrentReq
	if requestLimit <= 0 {
		requestLimit = defaultMaxConcurrentReq
	}

	session := &tunnelSession{
		id:           sessionID,
		token:        token,
		subdomain:    subdomain,
		clientIP:     ip,
		fingerprint:  fingerprint,
		allowedPaths: req.AllowedPaths,
		expiresAt:    exp,
		pending:      make(map[string]chan tunnelMessage),
		wsConns:      make(map[string]*bridgeConn),
		requestSlots: make(chan struct{}, requestLimit),
	}
	s.sessions[sessionID] = session
	s.bySubdomain[subdomain] = sessionID
	s.ipSessionNum[ip]++

	wsEndpoint := s.buildWSEndpoint(r, sessionID)
	publicURL := s.buildPublicURL(r, subdomain, s.rootDomain)
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
	s.decIPSessionCount(session.clientIP)
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
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "session_id required"})
		return
	}

	s.mu.RLock()
	session, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, apiError{Error: "session not found"})
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

	_ = conn.SetReadDeadline(time.Now().Add(wsAuthTimeout))
	var authMsg tunnelMessage
	if err := conn.ReadJSON(&authMsg); err != nil || authMsg.Type != "auth" {
		_ = conn.WriteJSON(tunnelMessage{Type: "error", Message: "auth message required within 5s"})
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if authMsg.Token != session.token {
		_ = conn.WriteJSON(tunnelMessage{Type: "error", Message: "invalid token"})
		_ = conn.Close()
		return
	}

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
			"service":     "godemo-gateway",
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

	if !session.pathAllowed(r.URL.Path) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "path not allowed"})
		return
	}

	if websocket.IsWebSocketUpgrade(r) {
		s.handlePublicWebSocket(w, r, session)
		return
	}
	s.handlePublicHTTP(w, r, session)
}

func (s *server) handlePublicHTTP(w http.ResponseWriter, r *http.Request, session *tunnelSession) {
	if !session.tryAcquireRequestSlot() {
		writeJSON(w, http.StatusTooManyRequests, apiError{Error: "too many concurrent requests for this tunnel"})
		return
	}
	defer session.releaseRequestSlot()

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
	msg.Headers["x-forwarded-proto"] = []string{s.requestProto(r)}
	msg.Headers["x-forwarded-for"] = []string{s.remoteIP(r)}
	log.Printf(
		"tunnel request session=%s req=%s method=%s path=%s query=%s body_bytes=%d host=%s",
		session.id,
		reqID,
		r.Method,
		r.URL.Path,
		sanitizeQuery(r.URL.RawQuery),
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
