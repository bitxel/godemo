package main

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

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
	id           string
	token        string
	subdomain    string
	clientIP     string
	fingerprint  string
	allowedPaths []string
	expiresAt    time.Time

	conn   *websocket.Conn
	connMu sync.RWMutex
	writeM sync.Mutex

	pending   map[string]chan tunnelMessage
	pendingMu sync.Mutex

	wsConns   map[string]*bridgeConn
	wsConnsMu sync.Mutex

	requestSlots chan struct{}
}

func (s *tunnelSession) isExpired(now time.Time) bool {
	return now.After(s.expiresAt)
}

// pathAllowed returns true if the request path is permitted.
// An empty allowedPaths list means all paths are allowed.
func (s *tunnelSession) pathAllowed(reqPath string) bool {
	if len(s.allowedPaths) == 0 {
		return true
	}
	for _, prefix := range s.allowedPaths {
		if reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/") {
			return true
		}
	}
	return false
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

func (s *tunnelSession) tryAcquireRequestSlot() bool {
	if s.requestSlots == nil {
		return true
	}
	select {
	case s.requestSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *tunnelSession) releaseRequestSlot() {
	if s.requestSlots == nil {
		return
	}
	select {
	case <-s.requestSlots:
	default:
	}
}
