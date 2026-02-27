# demoit Python SDK

## Install and Run

```bash
pip install demoit
demoit 3000
```

## Code integration: expose a running port

```python
import demoit

tunnel = demoit.expose(8000)
print(tunnel.public_url)
input("Press Enter to stop...")
tunnel.close()
```

## Code integration: expose a FastAPI/Flask app

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

## Environment variables

- `DEMOIT_GATEWAY_URL` -- override the default public gateway
