# godemo Python SDK

## Install and Run

```bash
pip install godemo
godemo 3000
```

## Code integration: expose a running port

```python
import godemo

tunnel = godemo.expose(8000)
print(tunnel.public_url)
input("Press Enter to stop...")
tunnel.close()
```

## Code integration: expose a FastAPI/Flask app

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

## Environment variables

- `GODEMO_GATEWAY_URL` -- override the default public gateway
