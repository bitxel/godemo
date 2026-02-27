package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnvString(t *testing.T) {
	t.Setenv("TEST_ENV_STR", "hello")
	if v := envString("TEST_ENV_STR", "default"); v != "hello" {
		t.Fatalf("expected hello, got %s", v)
	}
	if v := envString("TEST_ENV_STR_MISSING", "default"); v != "default" {
		t.Fatalf("expected default, got %s", v)
	}

	t.Setenv("TEST_ENV_WHITESPACE", "  ")
	if v := envString("TEST_ENV_WHITESPACE", "fallback"); v != "fallback" {
		t.Fatalf("expected fallback for whitespace-only, got %q", v)
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("TEST_ENV_INT", "42")
	if v := envInt("TEST_ENV_INT", 0); v != 42 {
		t.Fatalf("expected 42, got %d", v)
	}

	t.Setenv("TEST_ENV_INT_BAD", "notanumber")
	if v := envInt("TEST_ENV_INT_BAD", 99); v != 99 {
		t.Fatalf("expected fallback 99 for invalid int, got %d", v)
	}

	if v := envInt("TEST_ENV_INT_MISSING", 7); v != 7 {
		t.Fatalf("expected fallback 7, got %d", v)
	}

	t.Setenv("TEST_ENV_INT_NEGATIVE", "-5")
	if v := envInt("TEST_ENV_INT_NEGATIVE", 0); v != -5 {
		t.Fatalf("expected -5, got %d", v)
	}
}

func TestListToSet(t *testing.T) {
	set := listToSet("a, b ,c")
	for _, want := range []string{"a", "b", "c"} {
		if _, ok := set[want]; !ok {
			t.Fatalf("expected %q in set", want)
		}
	}
	if len(set) != 3 {
		t.Fatalf("expected 3 items, got %d", len(set))
	}

	empty := listToSet("")
	if len(empty) != 0 {
		t.Fatalf("expected empty set for empty string, got %d items", len(empty))
	}

	single := listToSet("onlyone")
	if _, ok := single["onlyone"]; !ok {
		t.Fatalf("expected 'onlyone' in set")
	}

	withBlanks := listToSet("a,,b, ,c")
	if len(withBlanks) != 3 {
		t.Fatalf("expected 3 items (blanks filtered), got %d", len(withBlanks))
	}
}

func TestHostWithoutPort(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:8080", "::1"},
		{"127.0.0.1:443", "127.0.0.1"},
		{"", ""},
	}
	for _, tc := range cases {
		got := hostWithoutPort(tc.input)
		if got != tc.want {
			t.Errorf("hostWithoutPort(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRemoteIPTrustProxy(t *testing.T) {
	s := &server{trustProxy: true}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	if ip := s.remoteIP(r); ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1 from RemoteAddr, got %s", ip)
	}

	r.Header.Set("X-Forwarded-For", " 203.0.113.1 , 10.0.0.1 ")
	if ip := s.remoteIP(r); ip != "203.0.113.1" {
		t.Fatalf("expected 203.0.113.1 from XFF with trustProxy=true, got %s", ip)
	}
}

func TestRemoteIPNoTrustProxy(t *testing.T) {
	s := &server{trustProxy: false}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	if ip := s.remoteIP(r); ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1 (ignore XFF when trustProxy=false), got %s", ip)
	}
}

func TestRemoteIPBadAddr(t *testing.T) {
	s := &server{trustProxy: false}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "badaddr"
	if ip := s.remoteIP(r); ip != "badaddr" {
		t.Fatalf("expected raw badaddr fallback, got %s", ip)
	}
}

func TestCloneHeader(t *testing.T) {
	h := http.Header{
		"Content-Type":  {"application/json"},
		"X-Custom":      {"a", "b"},
		"Authorization": {"Bearer token"},
	}
	cloned := cloneHeader(h)

	if len(cloned) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(cloned))
	}
	if ct := cloned["content-type"]; len(ct) != 1 || ct[0] != "application/json" {
		t.Fatalf("unexpected content-type: %v", ct)
	}
	if xc := cloned["x-custom"]; len(xc) != 2 || xc[0] != "a" || xc[1] != "b" {
		t.Fatalf("unexpected x-custom: %v", xc)
	}

	h.Set("Content-Type", "text/html")
	if cloned["content-type"][0] != "application/json" {
		t.Fatal("clone was not deep: mutation propagated")
	}
}

func TestRequestProto(t *testing.T) {
	s := &server{trustProxy: true}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if p := s.requestProto(r); p != "http" {
		t.Fatalf("expected http, got %s", p)
	}

	r.Header.Set("X-Forwarded-Proto", "HTTPS")
	if p := s.requestProto(r); p != "https" {
		t.Fatalf("expected https from XFP with trustProxy=true, got %s", p)
	}

	r.Header.Set("X-Forwarded-Proto", "  Http  ")
	if p := s.requestProto(r); p != "http" {
		t.Fatalf("expected http (trimmed+lowered), got %s", p)
	}
}

func TestRequestProtoIgnoresXFPWithoutTrustProxy(t *testing.T) {
	s := &server{trustProxy: false}

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if p := s.requestProto(r); p != "http" {
		t.Fatalf("expected http (ignore XFP when trustProxy=false), got %s", p)
	}
}

func TestReadRequestBody(t *testing.T) {
	body := strings.NewReader("hello world")
	r := httptest.NewRequest(http.MethodPost, "/", body)
	data, err := readRequestBody(r, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "hello world" {
		t.Fatalf("unexpected body: %s", string(data))
	}
}

func TestReadRequestBodyTooLarge(t *testing.T) {
	body := strings.NewReader("this is way too long")
	r := httptest.NewRequest(http.MethodPost, "/", body)
	_, err := readRequestBody(r, 5)
	if err == nil || err.Error() != "request body too large" {
		t.Fatalf("expected 'request body too large' error, got %v", err)
	}
}

func TestReadRequestBodyExactLimit(t *testing.T) {
	body := strings.NewReader("12345")
	r := httptest.NewRequest(http.MethodPost, "/", body)
	data, err := readRequestBody(r, 5)
	if err != nil {
		t.Fatalf("unexpected error at exact limit: %v", err)
	}
	if string(data) != "12345" {
		t.Fatalf("unexpected body: %s", string(data))
	}
}

func TestReadRequestBodyEmpty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	data, err := readRequestBody(r, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty body, got %d bytes", len(data))
	}
}

func TestRandHex(t *testing.T) {
	h1 := randHex(8)
	h2 := randHex(8)
	if len(h1) != 16 {
		t.Fatalf("randHex(8) should produce 16 hex chars, got %d", len(h1))
	}
	if h1 == h2 {
		t.Fatal("two randHex calls should not produce the same value")
	}
}

func TestDeterministicSubdomain(t *testing.T) {
	s1 := deterministicSubdomain("fp1", 3000)
	s2 := deterministicSubdomain("fp1", 3000)
	if s1 != s2 {
		t.Fatalf("same input should yield same subdomain: %s vs %s", s1, s2)
	}
	if !strings.HasPrefix(s1, "dm-") {
		t.Fatalf("expected dm- prefix, got %s", s1)
	}
	if len(s1) != 19 {
		t.Fatalf("expected 19 chars (dm- + 16 hex), got %d (%s)", len(s1), s1)
	}

	s3 := deterministicSubdomain("fp1", 8080)
	if s1 == s3 {
		t.Fatal("different port should yield different subdomain")
	}

	s4 := deterministicSubdomain("fp2", 3000)
	if s1 == s4 {
		t.Fatal("different fingerprint should yield different subdomain")
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusTeapot, map[string]string{"msg": "tea"})
	if w.Code != http.StatusTeapot {
		t.Fatalf("expected 418, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), `"msg":"tea"`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestWriteForwardedResponse(t *testing.T) {
	w := httptest.NewRecorder()
	headers := map[string][]string{
		"X-Custom":          {"val1"},
		"Connection":        {"keep-alive"},
		"Transfer-Encoding": {"chunked"},
	}
	writeForwardedResponse(w, http.StatusOK, headers, []byte("body"))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Custom") != "val1" {
		t.Fatal("expected X-Custom header to be forwarded")
	}
	if w.Header().Get("Connection") != "" {
		t.Fatal("Connection header should be stripped")
	}
	if w.Header().Get("Transfer-Encoding") != "" {
		t.Fatal("Transfer-Encoding header should be stripped")
	}
	if w.Body.String() != "body" {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestWriteForwardedResponseZeroStatus(t *testing.T) {
	w := httptest.NewRecorder()
	writeForwardedResponse(w, 0, nil, []byte("ok"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status 0 should default to 502, got %d", w.Code)
	}
}

func TestBuildPublicURL(t *testing.T) {
	s := &server{trustProxy: false}
	r := httptest.NewRequest(http.MethodGet, "http://gw.example.com/", nil)
	url := s.buildPublicURL(r, "qs-abc", "example.com")
	if url != "http://qs-abc.example.com" {
		t.Fatalf("unexpected URL: %s", url)
	}
}

func TestBuildWSEndpoint(t *testing.T) {
	s := &server{trustProxy: false}
	r := httptest.NewRequest(http.MethodGet, "http://gw.example.com/", nil)
	r.Host = "gw.example.com"
	ep := s.buildWSEndpoint(r, "ses_123")
	if !strings.HasPrefix(ep, "ws://") {
		t.Fatalf("expected ws:// prefix, got %s", ep)
	}
	if !strings.Contains(ep, "session_id=ses_123") {
		t.Fatalf("expected session_id in endpoint: %s", ep)
	}
	if strings.Contains(ep, "token=") {
		t.Fatalf("token should NOT be in WS endpoint URL: %s", ep)
	}
}

func TestBuildWSEndpointHTTPS(t *testing.T) {
	s := &server{trustProxy: true}
	r := httptest.NewRequest(http.MethodGet, "https://gw.example.com/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Host = "gw.example.com"
	ep := s.buildWSEndpoint(r, "ses_123")
	if !strings.HasPrefix(ep, "wss://") {
		t.Fatalf("expected wss:// prefix for HTTPS, got %s", ep)
	}
}

func TestSanitizeQuery(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"", ""},
		{"foo=bar", "foo=bar"},
		{"token=secret123", "token=***"},
		{"key=abc&other=ok", "key=***&other=ok"},
		{"TOKEN=ABC&password=xyz", "TOKEN=***&password=***"},
		{"a=1&secret=s&b=2", "a=1&secret=***&b=2"},
		{"noeq", "noeq"},
	}
	for _, tc := range cases {
		got := sanitizeQuery(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeQuery(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestPathAllowed(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		path    string
		want    bool
	}{
		{"empty allows all", nil, "/anything", true},
		{"exact match", []string{"/api"}, "/api", true},
		{"prefix match", []string{"/api"}, "/api/users", true},
		{"no partial match", []string{"/api"}, "/api-v2", false},
		{"root blocked", []string{"/api"}, "/", false},
		{"multiple prefixes", []string{"/api", "/health"}, "/health", true},
		{"multiple prefixes blocked", []string{"/api", "/health"}, "/admin", false},
		{"nested prefix", []string{"/api/v1"}, "/api/v1/users", true},
		{"nested prefix parent blocked", []string{"/api/v1"}, "/api/v2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &tunnelSession{allowedPaths: tc.allowed}
			got := s.pathAllowed(tc.path)
			if got != tc.want {
				t.Errorf("pathAllowed(%q) with allowed=%v: got %v, want %v", tc.path, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestDecIPSessionCount(t *testing.T) {
	s := &server{ipSessionNum: map[string]int{"1.2.3.4": 3, "5.6.7.8": 1}}
	s.decIPSessionCount("1.2.3.4")
	if s.ipSessionNum["1.2.3.4"] != 2 {
		t.Fatalf("expected 2, got %d", s.ipSessionNum["1.2.3.4"])
	}
	s.decIPSessionCount("5.6.7.8")
	if _, exists := s.ipSessionNum["5.6.7.8"]; exists {
		t.Fatal("zero-count IP should be deleted from map")
	}
	s.decIPSessionCount("9.9.9.9")
	if _, exists := s.ipSessionNum["9.9.9.9"]; exists {
		t.Fatal("negative-count IP should be deleted from map")
	}
}
