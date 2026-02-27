package main

// tunnelMessage is the envelope for all messages on the tunnel WebSocket.
// Fields are only populated when relevant for the specific message type.
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
