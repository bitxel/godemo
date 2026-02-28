# godemo

Expose any local HTTP or WebSocket service to the internet through a public URL.
One command, no signup, no config.

**How it works:** A Go gateway runs on a public server. The SDK (Python or Go client)
connects to it via WebSocket and forwards incoming HTTP/WS requests to your local port.

## Install

**One-liner (macOS / Linux / WSL):**

```bash
curl -fsSL https://raw.githubusercontent.com/bitxel/godemo/main/install.sh | bash
```

This downloads the latest `godemo-cli` binary to `~/.local/bin`. To install both the CLI and the gateway:

```bash
curl -fsSL https://raw.githubusercontent.com/bitxel/godemo/main/install.sh | bash -s -- --component all
```

**Other methods:**

| Method | Command |
|--------|---------|
| pip (Python SDK + CLI) | `pip install godemo` |
| Homebrew (coming soon) | `brew install bitxel/tap/godemo` |
| Go binary (manual) | See [Go Client](#go-client-binary) below |

## Quick Start

```bash
godemo-cli 3000          # 3000 is your local port
```

Output:

```
  godemo tunnel active

  Public URL:  https://dm-a355898a.0x0f.me
  Forwarding:  127.0.0.1:3000

  Press Ctrl+C to stop.
```

Anyone on the internet can now reach your local `:3000` via the public URL.

## Local Development

One-time setup:

```bash
make setup-python-dev
```

Run all tests:

```bash
make test
```

Gateway-only checks:

```bash
make test-go-race
make test-go-cover
```

### Path Whitelist

Restrict which paths are accessible through the tunnel. Requests to non-whitelisted paths
receive a `403 Forbidden` response from the gateway — they never reach your local server.

```bash
godemo-cli 3000 --allow-path /api --allow-path /health
```

Output:

```
  godemo tunnel active

  Public URL:  https://dm-a355898a.0x0f.me
  Forwarding:  127.0.0.1:3000
  Allowed:     /api, /health

  Press Ctrl+C to stop.
```

- `/api`, `/api/users`, `/api/v1/data` — allowed (prefix match)
- `/health` — allowed (exact match)
- `/admin`, `/`, `/api-v2` — blocked with 403

If `--allow-path` is omitted, all paths are allowed (default behavior).

## Go Client (Binary)

The recommended way to install the Go client is with the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/bitxel/godemo/main/install.sh | bash
```

Or download a pre-built binary manually from [GitHub Releases](https://github.com/bitxel/godemo/releases):

```bash
# Linux amd64
curl -Lo godemo-cli https://github.com/bitxel/godemo/releases/latest/download/godemo-cli-linux-amd64
chmod +x godemo-cli && mv godemo-cli ~/.local/bin/

# macOS Apple Silicon
curl -Lo godemo-cli https://github.com/bitxel/godemo/releases/latest/download/godemo-cli-darwin-arm64
chmod +x godemo-cli && mv godemo-cli ~/.local/bin/
```

### Go Client CLI

```bash
godemo-cli <port> [--gateway URL] [--host HOST] [--allow-path PATH ...] [--verbose]
```

| Flag | Default | Description |
|------|---------|-------------|
| `port` | (required) | Local port to expose |
| `--gateway`, `-g` | `$GODEMO_GATEWAY_URL` or `https://godemo.0x0f.me` | Gateway URL |
| `--host` | `127.0.0.1` | Local bind host |
| `--allow-path` | (all paths) | Restrict to path prefix (repeatable) |
| `--verbose`, `-v` | off | Enable debug logging |

## Python SDK

### Expose an existing port

```python
import godemo

tunnel = godemo.expose(8000)
print(tunnel.public_url)   # https://dm-a355898a.0x0f.me
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

#### `godemo.expose(port, gateway_url=None, local_host="127.0.0.1", request_timeout_seconds=20.0, allowed_paths=None) -> Tunnel`

Create a tunnel to a local port that is already listening.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `port` | `int` | (required) | Local port to expose |
| `gateway_url` | `str \| None` | `$GODEMO_GATEWAY_URL` or `https://godemo.0x0f.me` | Gateway URL |
| `local_host` | `str` | `"127.0.0.1"` | Local bind host |
| `request_timeout_seconds` | `float` | `20.0` | Timeout for local HTTP requests |
| `allowed_paths` | `list[str] \| None` | `None` (all paths) | Restrict to these path prefixes |

#### `godemo.share_app(app, host="127.0.0.1", port=0, gateway_url=None, request_timeout_seconds=20.0) -> Tunnel`

Start a local server for a WSGI/ASGI app and create a tunnel.

#### `Tunnel`

| Attribute / Method | Description |
|-------------------|-------------|
| `.public_url` | The public URL (e.g. `https://dm-a355898a.0x0f.me`) |
| `.session_id` | Gateway session ID |
| `.close()` | Shut down the tunnel |
| context manager | `with godemo.expose(8000) as t:` auto-closes |

### CLI

```bash
godemo-cli <port> [--gateway URL] [--host HOST] [--allow-path PATH ...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `port` | (required) | Local port to expose |
| `--gateway` | `$GODEMO_GATEWAY_URL` or `https://godemo.0x0f.me` | Gateway URL |
| `--host` | `127.0.0.1` | Local bind host |
| `--allow-path` | (all paths) | Restrict to path prefix (repeatable) |

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
GODEMO_GATEWAY_URL=https://tunnel.yourdomain.com godemo-cli 3000
```

See [`docs/gateway_deployment.md`](docs/gateway_deployment.md) for full Nginx/Caddy/systemd setup.

### Gateway Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GODEMO_ADDR` | `:8080` | Listen address |
| `GODEMO_ROOT_DOMAIN` | `0x0f.me` | Root domain for tunnel subdomains |
| `GODEMO_SESSION_TTL_SECONDS` | `7200` | Session time-to-live |
| `GODEMO_REQUEST_TIMEOUT_SECONDS` | `20` | HTTP request timeout |
| `GODEMO_MAX_SESSIONS_PER_IP` | `5` | Max active sessions per IP |
| `GODEMO_MAX_CREATE_PER_MINUTE` | `20` | Session creation rate limit |
| `GODEMO_MAX_CONCURRENT_REQUESTS_PER_SESSION` | `32` | Max concurrent forwarded HTTP requests per tunnel session |
| `GODEMO_DENY_IPS` | (empty) | Comma-separated IP deny list |
| `GODEMO_ALLOW_IPS` | (empty) | Comma-separated IP allow list |
| `GODEMO_TRUST_PROXY` | `false` | Trust proxy-provided `X-Forwarded-For` and `X-Forwarded-Proto` headers |
| `GODEMO_TRUSTED_PROXY_CIDRS` | (empty) | Comma-separated trusted proxy CIDRs/IPs used when `GODEMO_TRUST_PROXY=true` |

### SDK Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GODEMO_GATEWAY_URL` | `https://godemo.0x0f.me` | Gateway URL used by the SDK |

## Project Structure

- `gateway/` — Go reverse-proxy gateway
- `sdk/go/` — Go tunnel client CLI
- `sdk/python/` — Python SDK and CLI
- `docs/` — Protocol spec, abuse controls, deployment guide
- `examples/` — Usage examples

## Contributing

- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Security policy: [`SECURITY.md`](SECURITY.md)

## License

MIT
