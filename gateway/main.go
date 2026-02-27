package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
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
	defaultMaxConcurrentReq   = 32
	defaultMaxHTTPBodyBytes   = 8 * 1024 * 1024
	defaultMaxWSMessageBytes  = 8 * 1024 * 1024
	defaultCleanupIntervalSec = 30
	wsAuthTimeout             = 5 * time.Second
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
	Token        string              `json:"token,omitempty"`
}

type createSessionRequest struct {
	TTLSeconds   int      `json:"ttl_seconds"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	Port         int      `json:"port,omitempty"`
	AllowedPaths []string `json:"allowed_paths,omitempty"`
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
	maxConcurrentReq int
	maxHTTPBodyBytes int64
	maxWSMessageSize int64
	trustProxy       bool

	allowIPs          map[string]struct{}
	denyIPs           map[string]struct{}
	trustedProxyCIDRs []*net.IPNet

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

	srv := &http.Server{Addr: s.addr, Handler: s.withLogging(mux)}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("received signal %v, shutting down gracefully...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	log.Printf("godemo gateway listening on %s with root domain %s", s.addr, s.rootDomain)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen failed: %v", err)
	}
	log.Println("gateway stopped")
}

func newServerFromEnv() *server {
	ttlSeconds := envInt("GODEMO_SESSION_TTL_SECONDS", int(defaultSessionTTL.Seconds()))
	requestTimeout := envInt("GODEMO_REQUEST_TIMEOUT_SECONDS", int(defaultRequestTimeout.Seconds()))

	return &server{
		addr:             envString("GODEMO_ADDR", defaultAddr),
		rootDomain:       envString("GODEMO_ROOT_DOMAIN", defaultRootDomain),
		sessionTTL:       time.Duration(ttlSeconds) * time.Second,
		requestTimeout:   time.Duration(requestTimeout) * time.Second,
		maxSessionsPerIP: envInt("GODEMO_MAX_SESSIONS_PER_IP", defaultMaxSessionsPerIP),
		createPerMinute:  envInt("GODEMO_MAX_CREATE_PER_MINUTE", defaultCreatePerMinute),
		maxConcurrentReq: envInt("GODEMO_MAX_CONCURRENT_REQUESTS_PER_SESSION", defaultMaxConcurrentReq),
		maxHTTPBodyBytes: int64(envInt("GODEMO_MAX_HTTP_BODY_BYTES", defaultMaxHTTPBodyBytes)),
		maxWSMessageSize: int64(envInt("GODEMO_MAX_WS_MESSAGE_BYTES", defaultMaxWSMessageBytes)),
		trustProxy:       envString("GODEMO_TRUST_PROXY", "false") == "true",
		allowIPs:         listToSet(envString("GODEMO_ALLOW_IPS", "")),
		denyIPs:          listToSet(envString("GODEMO_DENY_IPS", "")),
		trustedProxyCIDRs: parseCIDRs(
			envString("GODEMO_TRUSTED_PROXY_CIDRS", ""),
		),
		sessions:     make(map[string]*tunnelSession),
		bySubdomain:  make(map[string]string),
		ipSessionNum: make(map[string]int),
		ipCreates:    make(map[string]*createWindow),
	}
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
			s.decIPSessionCount(session.clientIP)
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

func (s *server) decIPSessionCount(ip string) {
	s.ipSessionNum[ip]--
	if s.ipSessionNum[ip] <= 0 {
		delete(s.ipSessionNum, ip)
	}
}

func (s *server) removeSessionLocked(sessionID string, session *tunnelSession) {
	delete(s.sessions, sessionID)
	delete(s.bySubdomain, session.subdomain)
	s.decIPSessionCount(session.clientIP)
	if conn := session.getConn(); conn != nil {
		_ = conn.Close()
	}
	go func() {
		session.closeAllBridgeConns()
		session.failAllPending(tunnelMessage{Type: "error", Message: "session replaced"})
	}()
}

func (s *server) buildWSEndpoint(r *http.Request, sessionID string) string {
	scheme := "ws"
	if s.requestProto(r) == "https" {
		scheme = "wss"
	}
	host := r.Host
	return fmt.Sprintf("%s://%s/api/v1/tunnel/ws?session_id=%s", scheme, host, sessionID)
}

func (s *server) buildPublicURL(r *http.Request, subdomain, rootDomain string) string {
	scheme := s.requestProto(r)
	return fmt.Sprintf("%s://%s.%s", scheme, subdomain, rootDomain)
}
