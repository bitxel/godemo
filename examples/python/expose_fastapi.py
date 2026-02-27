"""
Example: expose a FastAPI app directly with demoit.

    pip install demoit[asgi] fastapi
    python expose_fastapi.py
"""
from fastapi import FastAPI

import demoit

app = FastAPI()


@app.get("/")
def root():
    return {"message": "hello from FastAPI via demoit"}


@app.get("/api/status")
def status():
    return {"status": "ok", "tunneled": True}


if __name__ == "__main__":
    tunnel = demoit.expose_app(app, gateway_url="http://127.0.0.1:8080")
    print(f"Public URL: {tunnel.public_url}")
    try:
        input("Press Enter to stop...")
    finally:
        tunnel.close()
