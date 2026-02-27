# demoit

Share your localhost app with one command. No signup, no config.

## Install and Run

```bash
pip install demoit
demoit 3000
```

## In Your Python Code

### Expose an existing port

```python
import demoit

tunnel = demoit.expose(8000)
print(tunnel.public_url)
```

### Expose a FastAPI app directly

```python
from fastapi import FastAPI
import demoit

app = FastAPI()

@app.get("/")
def root():
    return {"hello": "world"}

tunnel = demoit.expose_app(app)
print(tunnel.public_url)
```

## Self-Hosted Gateway

Run the gateway on your own VPS:

```bash
cd gateway
go build -o demoit-gateway .
DEMOIT_ROOT_DOMAIN=tunnel.yourdomain.com ./demoit-gateway
```

Then point the SDK at it:

```bash
DEMOIT_GATEWAY_URL=https://tunnel.yourdomain.com demoit 3000
```

## Project Structure

- `gateway/` -- Go reverse-proxy gateway
- `sdk/python/` -- Python SDK and CLI
- `docs/` -- Protocol spec, abuse controls, roadmap
- `examples/` -- Usage examples

## Gateway Environment Variables

| Variable | Default |
|----------|---------|
| `DEMOIT_ADDR` | `:8080` |
| `DEMOIT_ROOT_DOMAIN` | `0x0f.me` |
| `DEMOIT_SESSION_TTL_SECONDS` | `7200` |
| `DEMOIT_REQUEST_TIMEOUT_SECONDS` | `20` |
| `DEMOIT_MAX_SESSIONS_PER_IP` | `5` |
| `DEMOIT_MAX_CREATE_PER_MINUTE` | `20` |
| `DEMOIT_DENY_IPS` | (empty) |
| `DEMOIT_ALLOW_IPS` | (empty) |

## License

MIT
