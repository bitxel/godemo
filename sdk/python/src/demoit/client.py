from __future__ import annotations

import asyncio
import base64
import getpass
import hashlib
import json
import os
import platform
import signal
import sys
import threading
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
import websockets
from websockets.client import WebSocketClientProtocol

DEFAULT_GATEWAY_URL = os.environ.get("DEMOIT_GATEWAY_URL", "https://demoit.0x0f.me")


def _machine_fingerprint() -> str:
    raw = f"{platform.node()}:{uuid.getnode()}:{getpass.getuser()}"
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class _SessionInfo:
    session_id: str
    token: str
    public_url: str
    ws_endpoint: str


class _LocalWSBridge:
    def __init__(self, local_ws: WebSocketClientProtocol) -> None:
        self.local_ws = local_ws
        self.closed = asyncio.Event()


class Tunnel:
    """
    Long-lived demoit tunnel process.
    """

    def __init__(
        self,
        local_port: int,
        gateway_url: str,
        local_host: str = "127.0.0.1",
        request_timeout_seconds: float = 20.0,
    ) -> None:
        self.local_port = local_port
        self.local_host = local_host
        self.gateway_url = gateway_url.rstrip("/")
        self.request_timeout_seconds = request_timeout_seconds

        self.public_url: str | None = None
        self.session_id: str | None = None
        self._token: str | None = None

        self._thread: threading.Thread | None = None
        self._stop_flag = threading.Event()
        self._started = threading.Event()
        self._startup_error: Exception | None = None

    def start(self) -> "Tunnel":
        if self._thread is not None and self._thread.is_alive():
            return self
        self._thread = threading.Thread(target=self._run_in_thread, name="demoit-tunnel", daemon=True)
        self._thread.start()
        self._started.wait(timeout=15)
        if self._startup_error:
            raise self._startup_error
        if not self.public_url:
            raise RuntimeError("demoit tunnel failed to start")
        return self

    def close(self) -> None:
        self._stop_flag.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def __enter__(self) -> "Tunnel":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        self.close()

    def _run_in_thread(self) -> None:
        try:
            asyncio.run(self._run())
        except Exception as exc:  # pragma: no cover - startup signaling
            self._startup_error = exc
            self._started.set()

    async def _run(self) -> None:
        session = await self._create_session()
        self.session_id = session.session_id
        self._token = session.token
        self.public_url = session.public_url
        self._started.set()

        self._ws_write_lock = asyncio.Lock()

        async with websockets.connect(
            session.ws_endpoint,
            max_size=8 * 1024 * 1024,
            ping_interval=20,
            ping_timeout=20,
            close_timeout=3,
        ) as ws:
            await self._event_loop(ws)

        await self._delete_session()

    async def _ws_send(self, ws: WebSocketClientProtocol, payload: dict[str, Any]) -> None:
        async with self._ws_write_lock:
            await ws.send(json.dumps(payload))

    async def _event_loop(self, ws: WebSocketClientProtocol) -> None:
        local_ws_bridges: dict[str, _LocalWSBridge] = {}
        tasks: set[asyncio.Task[Any]] = set()

        try:
            while not self._stop_flag.is_set():
                try:
                    raw_msg = await asyncio.wait_for(ws.recv(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if isinstance(raw_msg, bytes):
                    raw_msg = raw_msg.decode("utf-8")
                msg = json.loads(raw_msg)
                msg_type = msg.get("type")

                if msg_type == "request":
                    task = asyncio.create_task(self._handle_http_request(ws, msg))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
                elif msg_type == "ws_open":
                    await self._handle_ws_open(ws, msg, local_ws_bridges, tasks)
                elif msg_type == "ws_data":
                    await self._handle_ws_data(msg, local_ws_bridges)
                elif msg_type == "ws_close":
                    await self._handle_ws_close(msg, local_ws_bridges)
                elif msg_type == "ping":
                    await self._ws_send(ws, {"type": "pong"})
                elif msg_type == "error":
                    print(f"[demoit] gateway error: {msg.get('message', 'unknown')}")
        finally:
            for bridge in local_ws_bridges.values():
                await bridge.local_ws.close()
            for task in tasks:
                task.cancel()

    async def _handle_http_request(self, ws: WebSocketClientProtocol, msg: dict[str, Any]) -> None:
        request_id = msg["request_id"]
        method = msg["method"]
        path = msg.get("path", "/")
        query = msg.get("query", "")
        headers = msg.get("headers", {})
        body_b64 = msg.get("body_b64", "")
        body = base64.b64decode(body_b64.encode("utf-8")) if body_b64 else b""

        url = f"http://{self.local_host}:{self.local_port}{path}"
        if query:
            url = f"{url}?{query}"

        try:
            async with httpx.AsyncClient(timeout=self.request_timeout_seconds) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    content=body,
                    headers={k: ",".join(v) if isinstance(v, list) else str(v) for k, v in headers.items()},
                )
            response_headers: dict[str, list[str]] = {}
            for key, value in resp.headers.multi_items():
                lk = key.lower()
                if lk not in response_headers:
                    response_headers[lk] = []
                response_headers[lk].append(value)

            payload = {
                "type": "response",
                "request_id": request_id,
                "status": resp.status_code,
                "headers": response_headers,
                "body_b64": base64.b64encode(resp.content).decode("utf-8"),
            }
        except Exception as exc:
            payload = {
                "type": "response",
                "request_id": request_id,
                "status": 502,
                "headers": {"content-type": ["application/json"]},
                "body_b64": base64.b64encode(
                    json.dumps({"error": f"local request failed: {exc}"}).encode("utf-8")
                ).decode("utf-8"),
            }
        await self._ws_send(ws, payload)

    async def _handle_ws_open(
        self,
        ws: WebSocketClientProtocol,
        msg: dict[str, Any],
        bridges: dict[str, _LocalWSBridge],
        tasks: set[asyncio.Task[Any]],
    ) -> None:
        connection_id = msg["connection_id"]
        path = msg.get("path", "/")
        query = msg.get("query", "")
        target = f"ws://{self.local_host}:{self.local_port}{path}"
        if query:
            target = f"{target}?{query}"

        try:
            local_ws = await websockets.connect(target, max_size=8 * 1024 * 1024)
            bridge = _LocalWSBridge(local_ws)
            bridges[connection_id] = bridge

            async def _pump_local_to_gateway() -> None:
                try:
                    async for payload in local_ws:
                        if isinstance(payload, str):
                            opcode = "text"
                            raw = payload.encode("utf-8")
                        else:
                            opcode = "binary"
                            raw = payload
                        await self._ws_send(
                            ws,
                            {
                                "type": "ws_data",
                                "connection_id": connection_id,
                                "opcode": opcode,
                                "data_b64": base64.b64encode(raw).decode("utf-8"),
                            },
                        )
                finally:
                    await self._ws_send(
                        ws,
                        {
                            "type": "ws_close",
                            "connection_id": connection_id,
                            "code": 1000,
                            "reason": "local websocket closed",
                        },
                    )
                    bridge.closed.set()

            task = asyncio.create_task(_pump_local_to_gateway())
            tasks.add(task)
            task.add_done_callback(tasks.discard)
        except Exception as exc:
            await self._ws_send(
                ws,
                {
                    "type": "ws_close",
                    "connection_id": connection_id,
                    "code": 1011,
                    "reason": f"unable to open local websocket: {exc}",
                },
            )

    async def _handle_ws_data(self, msg: dict[str, Any], bridges: dict[str, _LocalWSBridge]) -> None:
        connection_id = msg.get("connection_id", "")
        bridge = bridges.get(connection_id)
        if not bridge:
            return
        payload = base64.b64decode(msg.get("data_b64", "").encode("utf-8"))
        opcode = msg.get("opcode", "text")
        if opcode == "binary":
            await bridge.local_ws.send(payload)
        else:
            await bridge.local_ws.send(payload.decode("utf-8", errors="replace"))

    async def _handle_ws_close(self, msg: dict[str, Any], bridges: dict[str, _LocalWSBridge]) -> None:
        connection_id = msg.get("connection_id", "")
        bridge = bridges.pop(connection_id, None)
        if not bridge:
            return
        await bridge.local_ws.close()

    async def _create_session(self) -> _SessionInfo:
        payload: dict[str, Any] = {
            "ttl_seconds": 0,
            "fingerprint": _machine_fingerprint(),
            "port": self.local_port,
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(f"{self.gateway_url}/api/v1/sessions", json=payload)
            resp.raise_for_status()
            data = resp.json()
        return _SessionInfo(
            session_id=data["session_id"],
            token=data["token"],
            public_url=data["public_url"],
            ws_endpoint=data["ws_endpoint"],
        )

    async def _delete_session(self) -> None:
        if not self.session_id or not self._token:
            return
        headers = {"Authorization": f"Bearer {self._token}"}
        async with httpx.AsyncClient(timeout=5) as client:
            try:
                await client.delete(f"{self.gateway_url}/api/v1/sessions/{self.session_id}", headers=headers)
            except Exception:
                pass


def expose(
    port: int,
    gateway_url: str | None = None,
    local_host: str = "127.0.0.1",
    request_timeout_seconds: float = 20.0,
) -> Tunnel:
    """
    One-line entrypoint:
        tunnel = demoit.expose(8000)
    """
    tunnel = Tunnel(
        local_port=port,
        local_host=local_host,
        gateway_url=gateway_url or DEFAULT_GATEWAY_URL,
        request_timeout_seconds=request_timeout_seconds,
    )
    return tunnel.start()


def expose_app(
    app: Any,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    gateway_url: str | None = None,
    request_timeout_seconds: float = 20.0,
) -> Tunnel:
    """
    Expose a WSGI/ASGI app (FastAPI, Flask, etc.) directly.

    Starts a local server for the app, then creates a tunnel.
    Returns the Tunnel with .public_url set.

    Example:
        from fastapi import FastAPI
        import demoit

        app = FastAPI()

        @app.get("/")
        def root():
            return {"hello": "world"}

        tunnel = demoit.expose_app(app)
        print(tunnel.public_url)
    """
    import socket
    import threading as _threading

    if port == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, 0))
            port = s.getsockname()[1]

    _is_asgi = _looks_like_asgi(app)

    def _run_server() -> None:
        if _is_asgi:
            try:
                import uvicorn  # type: ignore[import-untyped]
            except ImportError:
                raise RuntimeError(
                    "uvicorn is required to serve ASGI apps. Install it: pip install uvicorn"
                )
            uvicorn.run(app, host=host, port=port, log_level="warning")
        else:
            try:
                from werkzeug.serving import make_server  # type: ignore[import-untyped]
            except ImportError:
                raise RuntimeError(
                    "werkzeug is required to serve WSGI apps. Install it: pip install werkzeug"
                )
            srv = make_server(host, port, app)
            srv.serve_forever()

    server_thread = _threading.Thread(target=_run_server, daemon=True, name="demoit-app-server")
    server_thread.start()

    import time as _time
    _time.sleep(0.3)

    return expose(
        port=port,
        gateway_url=gateway_url,
        local_host=host,
        request_timeout_seconds=request_timeout_seconds,
    )


def _looks_like_asgi(app: Any) -> bool:
    import inspect
    if hasattr(app, "__call__"):
        sig = inspect.signature(app.__call__ if hasattr(app, "__call__") else app)
        params = list(sig.parameters)
        if len(params) >= 3:
            names = {p.lower() for p in params[:3]}
            if names & {"scope", "receive", "send"}:
                return True
    if type(app).__module__.startswith(("fastapi", "starlette", "litestar", "quart")):
        return True
    return False


def run_cli() -> None:
    """
    CLI entrypoint for: python -m demoit 3000
    or: demoit 3000
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="demoit",
        description="Expose a local port to the internet via Demoit gateway.",
    )
    parser.add_argument("port", type=int, help="Local port to expose (e.g. 3000)")
    parser.add_argument(
        "--gateway",
        default=None,
        help=f"Gateway URL (default: $DEMOIT_GATEWAY_URL or {DEFAULT_GATEWAY_URL})",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Local bind host (default: 127.0.0.1)")

    args = parser.parse_args()

    tunnel = expose(port=args.port, gateway_url=args.gateway, local_host=args.host)

    print(f"\n  demoit tunnel active\n")
    print(f"  Public URL:  {tunnel.public_url}")
    print(f"  Forwarding:  {args.host}:{args.port}")
    print(f"\n  Press Ctrl+C to stop.\n")

    def _shutdown(sig: int, frame: Any) -> None:
        print("\n  Shutting down...")
        tunnel.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    signal.pause()
