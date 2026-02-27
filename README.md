# godemo

Expose any local HTTP or WebSocket service to the internet through a public URL.
One command, no signup, no config.

**How it works:** A Go gateway runs on a public server. The Python SDK connects to it
via WebSocket and forwards incoming HTTP/WS requests to your local port.

## Quick Start

```bash
pip install godemo
godemo 3000          # 3000 is your local port
```

Output:

```
  godemo tunnel active

  Public URL:  https://dm-7f3a1b2c.0x0f.me
  Forwarding:  127.0.0.1:3000

  Press Ctrl+C to stop.
```

Anyone on the internet can now reach your local `:3000` via the public URL.

## Python SDK

### Expose an existing port

```python
import godemo

tunnel = godemo.expose(8000)
print(tunnel.public_url)   # https://dm-xxxx.0x0f.me
input("Press Enter to stop...")
tunnel.close()
```

Or use a context manager:

```python
with godemo.expose(8000) as tunnel:
    print(tunnel.public_url)
    input("Press Enter to stop...")
```

### Expose a FastAPI / Flask app directly

```python
from fastapi import FastAPI
import godemo

app = FastAPI()

@app.get("/")
def root():
    return {"hello": "world"}

tunnel = godemo.share_app(app)
print(tunnel.public_url)
```

`share_app()` auto-detects ASGI (FastAPI, Starlette, Litestar, Quart) vs WSGI (Flask, Django)
and starts a local server automatically. Requires `pip install godemo[asgi]` or `pip install godemo[wsgi]`.

### API Reference

#### `godemo.expose(port, gateway_url=None, local_host="127.0.0.1", request_timeout_seconds=20.0) -> Tunnel`

Create a tunnel to a local port that is already listening.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `port` | `int` | (required) | Local port to expose |
| `gateway_url` | `str \| None` | `$GODEMO_GATEWAY_URL` or `https://godemo.0x0f.me` | Gateway URL |
| `local_host` | `str` | `"127.0.0.1"` | Local bind host |
| `request_timeout_seconds` | `float` | `20.0` | Timeout for local HTTP requests |

#### `godemo.share_app(app, host="127.0.0.1", port=0, gateway_url=None, request_timeout_seconds=20.0) -> Tunnel`

Start a local server for a WSGI/ASGI app and create a tunnel.

#### `Tunnel`

| Attribute / Method | Description |
|-------------------|-------------|
| `.public_url` | The public URL (e.g. `https://dm-xxxx.0x0f.me`) |
| `.session_id` | Gateway session ID |
| `.close()` | Shut down the tunnel |
| context manager | `with godemo.expose(8000) as t:` auto-closes |

### CLI

```bash
godemo <port> [--gateway URL] [--host HOST]
```

| Flag | Default | Description |
|------|---------|-------------|
| `port` | (required) | Local port to expose |
| `--gateway` | `$GODEMO_GATEWAY_URL` or `https://godemo.0x0f.me` | Gateway URL |
| `--host` | `127.0.0.1` | Local bind host |

The CLI can also be invoked as `python -m godemo`.

## Self-Hosted Gateway

Run the Go gateway on your own VPS:

```bash
cd gateway
go build -o godemo-gateway .
GODEMO_ROOT_DOMAIN=tunnel.yourdomain.com ./godemo-gateway
```

Then point the SDK at it:

```bash
GODEMO_GATEWAY_URL=https://tunnel.yourdomain.com godemo 3000
```

See [`docs/deployment.md`](docs/deployment.md) for full Nginx/Caddy/systemd setup.

### Gateway Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GODEMO_ADDR` | `:8080` | Listen address |
| `GODEMO_ROOT_DOMAIN` | `0x0f.me` | Root domain for tunnel subdomains |
| `GODEMO_SESSION_TTL_SECONDS` | `7200` | Session time-to-live |
| `GODEMO_REQUEST_TIMEOUT_SECONDS` | `20` | HTTP request timeout |
| `GODEMO_MAX_SESSIONS_PER_IP` | `5` | Max active sessions per IP |
| `GODEMO_MAX_CREATE_PER_MINUTE` | `20` | Session creation rate limit |
| `GODEMO_DENY_IPS` | (empty) | Comma-separated IP deny list |
| `GODEMO_ALLOW_IPS` | (empty) | Comma-separated IP allow list |
| `GODEMO_TRUST_PROXY` | `false` | Trust `X-Forwarded-Proto` header |

### SDK Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GODEMO_GATEWAY_URL` | `https://godemo.0x0f.me` | Gateway URL used by the SDK |

## Project Structure

- `gateway/` — Go reverse-proxy gateway
- `sdk/python/` — Python SDK and CLI
- `docs/` — Protocol spec, abuse controls, deployment guide
- `examples/` — Usage examples

## Contributing

- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Security policy: [`SECURITY.md`](SECURITY.md)

## License

MIT
