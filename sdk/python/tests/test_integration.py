"""
Integration tests that start a real gateway and verify end-to-end tunnel behavior.

These tests require Go to be installed (to build the gateway binary).
Skip gracefully if Go is not available.
"""

import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

GATEWAY_DIR = Path(__file__).resolve().parents[3] / "gateway"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _go_available() -> bool:
    return shutil.which("go") is not None


def _build_gateway() -> Path:
    binary = GATEWAY_DIR / "godemo-gateway-test"
    subprocess.check_call(
        ["go", "build", "-o", str(binary), "."],
        cwd=str(GATEWAY_DIR),
        timeout=60,
    )
    return binary


def _wait_for_server(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server {host}:{port} not ready within {timeout}s")


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP server that echoes requests back as JSON."""

    def do_GET(self) -> None:
        self._respond()

    def do_POST(self) -> None:
        self._respond()

    def _respond(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "body": body.decode("utf-8", errors="replace"),
                "echo": True,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        pass


@unittest.skipUnless(_go_available(), "Go not installed, skipping integration tests")
class IntegrationTests(unittest.TestCase):
    gateway_proc: subprocess.Popen | None = None
    gateway_port: int = 0
    local_port: int = 0
    local_server: http.server.HTTPServer | None = None
    local_thread: threading.Thread | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.gateway_binary = _build_gateway()

        cls.gateway_port = _find_free_port()
        cls.gateway_proc = subprocess.Popen(
            [str(cls.gateway_binary)],
            env={
                **os.environ,
                "GODEMO_ADDR": f":{cls.gateway_port}",
                "GODEMO_ROOT_DOMAIN": "localhost",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _wait_for_server("127.0.0.1", cls.gateway_port)

        cls.local_port = _find_free_port()
        cls.local_server = http.server.HTTPServer(
            ("127.0.0.1", cls.local_port),
            _EchoHandler,
        )
        cls.local_thread = threading.Thread(
            target=cls.local_server.serve_forever,
            daemon=True,
        )
        cls.local_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.gateway_proc:
            cls.gateway_proc.terminate()
            cls.gateway_proc.wait(timeout=5)
        if cls.local_server:
            cls.local_server.shutdown()
        binary = GATEWAY_DIR / "godemo-gateway-test"
        if binary.exists():
            binary.unlink()

    def test_healthz(self) -> None:
        url = f"http://127.0.0.1:{self.gateway_port}/api/healthz"
        resp = urlopen(url, timeout=5)
        data = json.loads(resp.read())
        self.assertEqual(data["status"], "ok")

    def test_session_create_and_delete(self) -> None:
        url = f"http://127.0.0.1:{self.gateway_port}/api/v1/sessions"
        req = Request(url, data=b"{}", headers={"Content-Type": "application/json"})
        resp = urlopen(req, timeout=5)
        self.assertEqual(resp.status, 201)
        data = json.loads(resp.read())
        self.assertIn("session_id", data)
        self.assertIn("token", data)

        del_url = (
            f"http://127.0.0.1:{self.gateway_port}/api/v1/sessions/{data['session_id']}"
        )
        del_req = Request(
            del_url,
            method="DELETE",
            headers={"Authorization": f"Bearer {data['token']}"},
        )
        del_resp = urlopen(del_req, timeout=5)
        self.assertEqual(del_resp.status, 200)

    def test_tunnel_end_to_end(self) -> None:
        """Full test: create tunnel via SDK, send HTTP through it, verify response."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from godemo.client import Tunnel

        gateway_url = f"http://127.0.0.1:{self.gateway_port}"
        tunnel = Tunnel(
            local_port=self.local_port,
            gateway_url=gateway_url,
            local_host="127.0.0.1",
        )
        tunnel.start()
        try:
            self.assertIsNotNone(tunnel.public_url)
            self.assertIsNotNone(tunnel.session_id)

            from urllib.parse import urlparse

            parsed = urlparse(tunnel.public_url)
            host_header = parsed.hostname

            # Retry a few times to allow the SDK WebSocket to fully connect.
            test_url = f"http://127.0.0.1:{self.gateway_port}/test-path?q=hello"
            last_err = None
            for _ in range(20):
                try:
                    req = Request(test_url, headers={"Host": host_header})
                    resp = urlopen(req, timeout=10)
                    data = json.loads(resp.read())
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(data["method"], "GET")
                    self.assertTrue(data["path"].startswith("/test-path"))
                    self.assertTrue(data["echo"])
                    return
                except URLError as exc:
                    last_err = exc
                    time.sleep(0.25)
            self.fail(f"tunnel request never succeeded: {last_err}")
        finally:
            tunnel.close()


def _werkzeug_available() -> bool:
    try:
        import werkzeug  # noqa: F401

        return True
    except ImportError:
        return False


@unittest.skipUnless(_go_available(), "Go not installed, skipping integration tests")
@unittest.skipUnless(_werkzeug_available(), "werkzeug not installed, skipping share_app tests")
class ShareAppIntegrationTests(unittest.TestCase):
    """End-to-end test for share_app with a WSGI app."""

    gateway_proc: subprocess.Popen | None = None
    gateway_port: int = 0

    @classmethod
    def setUpClass(cls) -> None:
        cls.gateway_binary = _build_gateway()
        cls.gateway_port = _find_free_port()
        cls.gateway_proc = subprocess.Popen(
            [str(cls.gateway_binary)],
            env={
                **os.environ,
                "GODEMO_ADDR": f":{cls.gateway_port}",
                "GODEMO_ROOT_DOMAIN": "localhost",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _wait_for_server("127.0.0.1", cls.gateway_port)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.gateway_proc:
            cls.gateway_proc.terminate()
            cls.gateway_proc.wait(timeout=5)
        binary = GATEWAY_DIR / "godemo-gateway-test"
        if binary.exists():
            binary.unlink()

    def test_share_wsgi_app_end_to_end(self) -> None:
        """share_app with a WSGI callable: auto-starts server and tunnels traffic."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from godemo.client import share_app

        def wsgi_app(environ: dict, start_response):  # type: ignore[type-arg]
            status = "200 OK"
            body = json.dumps({"wsgi": True, "path": environ["PATH_INFO"]}).encode()
            start_response(status, [("Content-Type", "application/json")])
            return [body]

        gateway_url = f"http://127.0.0.1:{self.gateway_port}"
        tunnel = share_app(wsgi_app, gateway_url=gateway_url)
        try:
            self.assertIsNotNone(tunnel.public_url)

            from urllib.parse import urlparse

            host_header = urlparse(tunnel.public_url).hostname

            test_url = f"http://127.0.0.1:{self.gateway_port}/wsgi-test"
            last_err = None
            for _ in range(20):
                try:
                    req = Request(test_url, headers={"Host": host_header})
                    resp = urlopen(req, timeout=10)
                    data = json.loads(resp.read())
                    self.assertEqual(resp.status, 200)
                    self.assertTrue(data["wsgi"])
                    self.assertEqual(data["path"], "/wsgi-test")
                    return
                except URLError as exc:
                    last_err = exc
                    time.sleep(0.25)
            self.fail(f"share_app tunnel request never succeeded: {last_err}")
        finally:
            tunnel.close()


if __name__ == "__main__":
    unittest.main()
