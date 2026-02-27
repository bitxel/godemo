package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --- helpers ---

func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func goAvailable() bool {
	_, err := exec.LookPath("go")
	return err == nil
}

var (
	gatewayBinaryPath string
	gatewayBuildOnce  sync.Once
	gatewayBuildErr   error
)

func buildGateway(t *testing.T) string {
	t.Helper()
	gatewayBuildOnce.Do(func() {
		gatewayDir := filepath.Join("..", "..", "gateway")
		abs, _ := filepath.Abs(filepath.Join(gatewayDir, "godemo-gateway-gotest"))
		cmd := exec.Command("go", "build", "-o", abs, ".")
		cmd.Dir = gatewayDir
		out, err := cmd.CombinedOutput()
		if err != nil {
			gatewayBuildErr = fmt.Errorf("build gateway: %v\n%s", err, out)
			return
		}
		gatewayBinaryPath = abs
	})
	if gatewayBuildErr != nil {
		t.Fatal(gatewayBuildErr)
	}
	return gatewayBinaryPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if gatewayBinaryPath != "" {
		os.Remove(gatewayBinaryPath)
	}
	os.Exit(code)
}

func waitForServer(t *testing.T, host string, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server %s:%d not ready within %s", host, port, timeout)
}

func startEchoServer(t *testing.T) (int, func()) {
	t.Helper()
	port := findFreePort(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
			"body":   string(body),
			"echo":   true,
		})
	})

	mux.HandleFunc("/echo-headers", func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string][]string)
		for k, vv := range r.Header {
			headers[strings.ToLower(k)] = vv
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo-Custom", "from-local-server")
		w.Header().Add("Set-Cookie", "token=abc; Path=/")
		w.Header().Add("Set-Cookie", "lang=en; Path=/")
		json.NewEncoder(w).Encode(map[string]any{
			"headers": headers,
		})
	})

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux.HandleFunc("/ws-echo", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	})

	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: mux}
	go srv.ListenAndServe()
	waitForServer(t, "127.0.0.1", port, 5*time.Second)
	return port, func() { srv.Close() }
}

func skipIfNoGo(t *testing.T) {
	t.Helper()
	if !goAvailable() {
		t.Skip("Go not installed, skipping integration tests")
	}
}

// setupTunnel starts a gateway, echo server, and Go client tunnel.
// Returns the gateway port, tunnel, host header for requests, and cleanup func.
func setupTunnel(t *testing.T, binary string) (int, *tunnel, string, func()) {
	t.Helper()

	gatewayPort := findFreePort(t)
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GODEMO_ADDR=:%d", gatewayPort),
		"GODEMO_ROOT_DOMAIN=localhost",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	waitForServer(t, "127.0.0.1", gatewayPort, 10*time.Second)

	echoPort, echoClose := startEchoServer(t)

	gatewayURL := fmt.Sprintf("http://127.0.0.1:%d", gatewayPort)
	tun := newTunnel(gatewayURL, "127.0.0.1", echoPort)

	if err := tun.createSession(); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		echoClose()
		t.Fatalf("createSession: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	if err := tun.connect(ctx); err != nil {
		cancel()
		tun.deleteSession()
		cmd.Process.Kill()
		cmd.Wait()
		echoClose()
		t.Fatalf("connect: %v", err)
	}

	go tun.eventLoop(ctx)

	if tun.publicURL == "" {
		t.Fatal("publicURL is empty")
	}

	parts := strings.SplitN(strings.TrimPrefix(tun.publicURL, "http://"), ".", 2)
	hostHeader := parts[0] + ".localhost"

	cleanup := func() {
		cancel()
		tun.close()
		cmd.Process.Kill()
		cmd.Wait()
		echoClose()
	}

	return gatewayPort, tun, hostHeader, cleanup
}

// --- integration tests ---

func TestIntegrationHTTPForwarding(t *testing.T) {
	skipIfNoGo(t)
	binary := buildGateway(t)
	gatewayPort, _, hostHeader, cleanup := setupTunnel(t, binary)
	defer cleanup()

	var lastErr error
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/test-path?q=hello", gatewayPort), nil)
		req.Host = hostHeader
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("status %d, body: %s", resp.StatusCode, body)
			time.Sleep(250 * time.Millisecond)
			continue
		}

		var data map[string]any
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if data["method"] != "GET" {
			t.Errorf("method = %v; want GET", data["method"])
		}
		if !strings.HasPrefix(data["path"].(string), "/test-path") {
			t.Errorf("path = %v; want /test-path*", data["path"])
		}
		if data["echo"] != true {
			t.Errorf("echo = %v; want true", data["echo"])
		}
		return
	}
	t.Fatalf("HTTP forwarding never succeeded: %v", lastErr)
}

func TestIntegrationHTTPPost(t *testing.T) {
	skipIfNoGo(t)
	binary := buildGateway(t)
	gatewayPort, _, hostHeader, cleanup := setupTunnel(t, binary)
	defer cleanup()

	var lastErr error
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/submit", gatewayPort), strings.NewReader(`{"key":"value"}`))
		req.Host = hostHeader
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("status %d, body: %s", resp.StatusCode, body)
			time.Sleep(250 * time.Millisecond)
			continue
		}

		var data map[string]any
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if data["method"] != "POST" {
			t.Errorf("method = %v; want POST", data["method"])
		}
		if data["body"] != `{"key":"value"}` {
			t.Errorf("body = %v; want %s", data["body"], `{"key":"value"}`)
		}
		return
	}
	t.Fatalf("HTTP POST forwarding never succeeded: %v", lastErr)
}

func TestIntegrationWSForwarding(t *testing.T) {
	skipIfNoGo(t)
	binary := buildGateway(t)
	gatewayPort, _, hostHeader, cleanup := setupTunnel(t, binary)
	defer cleanup()

	time.Sleep(500 * time.Millisecond)

	wsURL := fmt.Sprintf("ws://127.0.0.1:%d/ws-echo", gatewayPort)
	header := http.Header{"Host": {hostHeader}}

	var lastErr error
	for i := 0; i < 10; i++ {
		ws, _, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}

		testMsg := "hello via tunnel"
		if err := ws.WriteMessage(websocket.TextMessage, []byte(testMsg)); err != nil {
			ws.Close()
			lastErr = err
			continue
		}

		_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, reply, err := ws.ReadMessage()
		ws.Close()
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if string(reply) != testMsg {
			t.Errorf("WS echo = %q; want %q", string(reply), testMsg)
		}
		return
	}
	t.Fatalf("WebSocket forwarding never succeeded: %v", lastErr)
}

func TestIntegrationHTTPHeaderForwarding(t *testing.T) {
	skipIfNoGo(t)
	binary := buildGateway(t)
	gatewayPort, _, hostHeader, cleanup := setupTunnel(t, binary)
	defer cleanup()

	var lastErr error
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/echo-headers", gatewayPort), nil)
		req.Host = hostHeader
		req.Header.Set("Cookie", "session_id=abc123; theme=dark")
		req.Header.Set("X-Custom-Header", "my-custom-value")
		req.Header.Set("Authorization", "Bearer test-token-123")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Accept", "text/html")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("status %d, body: %s", resp.StatusCode, body)
			time.Sleep(250 * time.Millisecond)
			continue
		}

		var data struct {
			Headers map[string][]string `json:"headers"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		// Verify request headers reached the local server
		if cookie := data.Headers["cookie"]; len(cookie) == 0 || !strings.Contains(cookie[0], "session_id=abc123") {
			t.Errorf("cookie not forwarded: %v", data.Headers["cookie"])
		}
		if custom := data.Headers["x-custom-header"]; len(custom) == 0 || custom[0] != "my-custom-value" {
			t.Errorf("x-custom-header not forwarded: %v", data.Headers["x-custom-header"])
		}
		if auth := data.Headers["authorization"]; len(auth) == 0 || auth[0] != "Bearer test-token-123" {
			t.Errorf("authorization not forwarded: %v", data.Headers["authorization"])
		}

		// Verify response headers from local server are forwarded back
		if v := resp.Header.Get("X-Echo-Custom"); v != "from-local-server" {
			t.Errorf("x-echo-custom response header = %q; want 'from-local-server'", v)
		}
		setCookies := resp.Header.Values("Set-Cookie")
		if len(setCookies) < 2 {
			t.Errorf("expected 2 Set-Cookie headers, got %d: %v", len(setCookies), setCookies)
		}

		return
	}
	t.Fatalf("HTTP header forwarding never succeeded: %v", lastErr)
}

func TestIntegrationConcurrentHTTP(t *testing.T) {
	skipIfNoGo(t)
	binary := buildGateway(t)
	gatewayPort, _, hostHeader, cleanup := setupTunnel(t, binary)
	defer cleanup()

	time.Sleep(500 * time.Millisecond)

	const numRequests = 10
	var wg sync.WaitGroup
	errs := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/concurrent/%d", gatewayPort, idx), nil)
			req.Host = hostHeader
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

func TestIntegrationReconnectAfterWSDisconnect(t *testing.T) {
	skipIfNoGo(t)
	binary := buildGateway(t)

	gatewayPort := findFreePort(t)
	echoPort, echoClose := startEchoServer(t)
	defer echoClose()

	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GODEMO_ADDR=:%d", gatewayPort),
		"GODEMO_ROOT_DOMAIN=localhost",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	waitForServer(t, "127.0.0.1", gatewayPort, 10*time.Second)

	gatewayURL := fmt.Sprintf("http://127.0.0.1:%d", gatewayPort)
	tun := newTunnel(gatewayURL, "127.0.0.1", echoPort)

	if err := tun.createSession(); err != nil {
		t.Fatalf("createSession: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go tun.runWithReconnect(ctx)

	parts := strings.SplitN(strings.TrimPrefix(tun.publicURL, "http://"), ".", 2)
	hostHeader := parts[0] + ".localhost"

	// Verify forwarding works initially
	var lastErr error
	ok := false
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/before-disconnect", gatewayPort), nil)
		req.Host = hostHeader
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			ok = true
			break
		}
		lastErr = fmt.Errorf("status %d", resp.StatusCode)
		time.Sleep(250 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("initial request never succeeded: %v", lastErr)
	}

	// Force-close the WS connection from the client side to simulate network drop
	tun.wsMu.Lock()
	if tun.ws != nil {
		_ = tun.ws.Close()
	}
	tun.wsMu.Unlock()

	// Wait for runWithReconnect to reconnect (backoff starts at 1s)
	time.Sleep(3 * time.Second)

	// Verify forwarding works again after reconnect
	ok = false
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/after-reconnect", gatewayPort), nil)
		req.Host = hostHeader
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			var data map[string]any
			json.Unmarshal(body, &data)
			if data["echo"] == true {
				ok = true
				break
			}
		}
		lastErr = fmt.Errorf("status %d body=%s", resp.StatusCode, body)
		time.Sleep(250 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("post-reconnect request never succeeded: %v", lastErr)
	}
}
