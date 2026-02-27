# godemo

Share your localhost app with one command. No signup, no config.

## Install and Run

```bash
pip install godemo
godemo 3000
```

## In Your Python Code

### Expose an existing port

```python
import godemo

tunnel = godemo.expose(8000)
print(tunnel.public_url)
```

### Expose a FastAPI app directly

```python
from fastapi import FastAPI
import godemo

app = FastAPI()

@app.get("/")
def root():
    return {"hello": "world"}

tunnel = godemo.expose_app(app)
print(tunnel.public_url)
```

## Self-Hosted Gateway

Run the gateway on your own VPS:

```bash
cd gateway
go build -o godemo-gateway .
GODEMO_ROOT_DOMAIN=tunnel.yourdomain.com ./godemo-gateway
```

Then point the SDK at it:

```bash
GODEMO_GATEWAY_URL=https://tunnel.yourdomain.com godemo 3000
```

## Project Structure

- `gateway/` -- Go reverse-proxy gateway
- `sdk/python/` -- Python SDK and CLI
- `docs/` -- Protocol spec, abuse controls, roadmap
- `examples/` -- Usage examples

## Contributing

- Contribution guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Security policy: `SECURITY.md`

## Gateway Environment Variables

| Variable | Default |
|----------|---------|
| `GODEMO_ADDR` | `:8080` |
| `GODEMO_ROOT_DOMAIN` | `0x0f.me` |
| `GODEMO_SESSION_TTL_SECONDS` | `7200` |
| `GODEMO_REQUEST_TIMEOUT_SECONDS` | `20` |
| `GODEMO_MAX_SESSIONS_PER_IP` | `5` |
| `GODEMO_MAX_CREATE_PER_MINUTE` | `20` |
| `GODEMO_DENY_IPS` | (empty) |
| `GODEMO_ALLOW_IPS` | (empty) |
| `GODEMO_TRUST_PROXY` | `false` |

## License

MIT
