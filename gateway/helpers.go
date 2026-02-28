package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

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
		status = http.StatusBadGateway
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

func (s *server) remoteIP(r *http.Request) string {
	if s.trustProxy && s.isTrustedProxy(r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *server) requestProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if s.trustProxy && s.isTrustedProxy(r.RemoteAddr) {
		if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
			return strings.ToLower(strings.TrimSpace(forwarded))
		}
	}
	return "http"
}

func (s *server) isTrustedProxy(remoteAddr string) bool {
	if len(s.trustedProxyCIDRs) == 0 {
		return true
	}
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range s.trustedProxyCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func deterministicSubdomain(fingerprint string, port int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", fingerprint, port)))
	return "dm-" + hex.EncodeToString(h[:4])
}

var sensitiveQueryKeys = map[string]struct{}{
	"token": {}, "key": {}, "secret": {}, "password": {},
}

func sanitizeQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	pairs := strings.Split(rawQuery, "&")
	for i, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			if _, ok := sensitiveQueryKeys[strings.ToLower(kv[0])]; ok {
				pairs[i] = kv[0] + "=***"
			}
		}
	}
	return strings.Join(pairs, "&")
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

func parseCIDRs(v string) []*net.IPNet {
	out := make([]*net.IPNet, 0)
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(item); err == nil {
			out = append(out, network)
			continue
		}
		ip := net.ParseIP(item)
		if ip == nil {
			continue
		}
		maskBits := 32
		if ip.To4() == nil {
			maskBits = 128
		}
		out = append(out, &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(maskBits, maskBits),
		})
	}
	return out
}
