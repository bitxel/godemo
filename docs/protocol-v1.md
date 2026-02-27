# Godemo Tunnel Protocol V1

This document defines the control/data protocol between `godemo` SDK clients and the gateway.

## Transport

- Control + data messages are multiplexed on one persistent WebSocket connection.
- Gateway endpoint: `GET /api/v1/tunnel/ws?session_id=<id>&token=<token>`
- All messages are UTF-8 JSON objects.
- Binary payloads are base64 encoded.

## Envelope

Every message includes:

- `type` (string): message type.
- `request_id` (string, optional): correlation id for HTTP request/response.
- `connection_id` (string, optional): correlation id for public WebSocket connections.
- `timestamp` (int, optional): unix ms; advisory for diagnostics.

## Message Types

### 1. `request` (gateway -> sdk)

Used for public HTTP requests.

```json
{
  "type": "request",
  "request_id": "req_123",
  "method": "POST",
  "path": "/api/demo",
  "query": "a=1&b=2",
  "headers": {
    "content-type": ["application/json"],
    "x-forwarded-for": ["1.2.3.4"]
  },
  "body_b64": "eyJvayI6dHJ1ZX0="
}
```

### 2. `response` (sdk -> gateway)

HTTP response for a `request`.

```json
{
  "type": "response",
  "request_id": "req_123",
  "status": 200,
  "headers": {
    "content-type": ["application/json"]
  },
  "body_b64": "eyJyZXN1bHQiOiJvayJ9"
}
```

### 3. `ws_open` (gateway -> sdk)

Signals an incoming public WebSocket upgrade.

```json
{
  "type": "ws_open",
  "connection_id": "ws_abc",
  "path": "/socket",
  "query": "room=1",
  "headers": {
    "sec-websocket-protocol": ["chat"]
  }
}
```

### 4. `ws_data` (bidirectional)

WebSocket frame payload.

```json
{
  "type": "ws_data",
  "connection_id": "ws_abc",
  "opcode": "text",
  "data_b64": "aGVsbG8="
}
```

`opcode` values:

- `text`
- `binary`

### 5. `ws_close` (bidirectional)

Close a proxied WebSocket connection.

```json
{
  "type": "ws_close",
  "connection_id": "ws_abc",
  "code": 1000,
  "reason": "normal closure"
}
```

### 6. `ping` / `pong` (bidirectional)

Application-level heartbeat in addition to WebSocket keepalive.

```json
{
  "type": "ping"
}
```

```json
{
  "type": "pong"
}
```

### 7. `error` (bidirectional)

Protocol or forwarding level error.

```json
{
  "type": "error",
  "request_id": "req_123",
  "code": "UPSTREAM_TIMEOUT",
  "message": "local server did not respond in 20s"
}
```

## Session Creation

`POST /api/v1/sessions`

```json
{
  "ttl_seconds": 0,
  "fingerprint": "sha256-hex-string",
  "port": 3000
}
```

All fields are optional:

- `ttl_seconds`: Custom TTL (capped at server max). `0` uses the server default.
- `fingerprint`: SHA-256 hex digest of machine identity (hostname + MAC + username). When provided together with `port`, the gateway generates a **deterministic subdomain** using `dm-` + `hex(sha256(fingerprint + ":" + port))[:8]`.
- `port`: Local port being exposed. Used together with `fingerprint` for subdomain generation.

### Deterministic Subdomains

When both `fingerprint` and `port` are provided:

- The subdomain is computed as `dm-` + first 8 hex chars of `sha256(fingerprint + ":" + port)`.
- Same machine + same port always gets the same public URL.
- If the subdomain is already occupied by the same fingerprint, the old session is replaced.
- If occupied by a different fingerprint, the request is rejected with `409 Conflict`.

When `fingerprint` is omitted, the gateway falls back to a random `qs-` prefixed subdomain.

### Response

```json
{
  "session_id": "ses_abc123",
  "subdomain": "dm-7f3a1b2c",
  "public_url": "https://dm-7f3a1b2c.0x0f.me",
  "ws_endpoint": "wss://0x0f.me/api/v1/tunnel/ws?session_id=ses_abc123&token=...",
  "token": "...",
  "ttl_seconds": 7200,
  "expires_at": "2026-02-25T12:00:00Z"
}
```

## Root Domain Behavior

`GET /` on the root domain returns JSON gateway metadata.

## Limits

- Max JSON frame size: 8 MB.
- HTTP request timeout (gateway waiting for sdk response): 20s (default).
- Idle session timeout: configurable (default 2h).

## Compatibility

Backward compatibility is maintained per major version (`v1` here).
