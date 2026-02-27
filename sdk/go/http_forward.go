package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (t *tunnel) handleHTTPRequest(msg tunnelMessage) {
	requestID := msg.RequestID
	method := msg.Method
	path := msg.Path
	query := msg.Query
	headers := msg.Headers
	bodyB64 := msg.BodyB64

	body, _ := base64.StdEncoding.DecodeString(bodyB64)

	url := fmt.Sprintf("http://%s:%d%s", t.localHost, t.localPort, path)
	if query != "" {
		url = url + "?" + query
	}

	t0 := time.Now()
	logInfo("%s %s req=%s body=%d bytes", method, pathWithQuery(path, query), requestID, len(body))

	req, err := http.NewRequest(method, url, strings.NewReader(string(body)))
	if err != nil {
		t.sendErrorResponse(requestID, method, path, err, t0)
		return
	}

	for k, vv := range headers {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	client := &http.Client{Timeout: time.Duration(t.requestTimeout * float64(time.Second))}
	resp, err := client.Do(req)
	if err != nil {
		t.sendErrorResponse(requestID, method, path, err, t0)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.sendErrorResponse(requestID, method, path, err, t0)
		return
	}

	responseHeaders := make(map[string][]string)
	for k, vv := range resp.Header {
		lk := strings.ToLower(k)
		responseHeaders[lk] = vv
	}

	elapsed := time.Since(t0)
	logInfo("%s %s req=%s -> %d (%d bytes, %dms)", method, path, requestID, resp.StatusCode, len(respBody), elapsed.Milliseconds())

	payload := tunnelMessage{
		Type:      "response",
		RequestID: requestID,
		Status:    resp.StatusCode,
		Headers:   responseHeaders,
		BodyB64:   base64.StdEncoding.EncodeToString(respBody),
	}
	_ = t.wsSend(payload)
}

func (t *tunnel) sendErrorResponse(requestID, method, path string, err error, t0 time.Time) {
	elapsed := time.Since(t0)
	logError("%s %s req=%s -> 502 error=%v (%dms)", method, path, requestID, err, elapsed.Milliseconds())

	errBody := fmt.Sprintf(`{"error":"local request failed: %s"}`, err.Error())
	payload := tunnelMessage{
		Type:      "response",
		RequestID: requestID,
		Status:    502,
		Headers:   map[string][]string{"content-type": {"application/json"}},
		BodyB64:   base64.StdEncoding.EncodeToString([]byte(errBody)),
	}
	_ = t.wsSend(payload)
}

func pathWithQuery(path, query string) string {
	if query != "" {
		return path + "?" + query
	}
	return path
}
