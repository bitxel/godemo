# Abuse Controls V1

This document defines baseline anti-abuse controls for the managed public gateway.

## Anonymous Access Policy

- Anonymous sessions are allowed.
- Sessions are short-lived and strongly limited.

## Enforced Limits (Gateway Defaults)

- Per-IP max active sessions: `5`
- Per-IP create-session rate: `20/min`
- Per-session TTL: `2h`
- Per-request response timeout: `20s`
- Max request body: `8MB`
- Max WebSocket message size: `8MB`

## Blocking Controls

- Static deny list: `DEMOIT_DENY_IPS`
- Optional allow list mode: `DEMOIT_ALLOW_IPS`

## 429 Strategy

- `POST /api/v1/sessions` returns `429` when:
  - IP exceeds create-session rate, or
  - IP exceeds max active sessions.

Suggested response payload:

```json
{"error":"create session rate limited"}
```

## Next Iteration

- Add global bandwidth quotas per session.
- Add per-session concurrent upstream request caps.
- Add temporary ban after repeated abuse signals.
- Move rate-limit counters to Redis for multi-instance consistency.
