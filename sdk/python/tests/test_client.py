import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from godemo.client import (
    Tunnel,
    expose,
    share_app,
    _looks_like_asgi,
    _machine_fingerprint,
    _fix_ws_scheme,
    _fix_public_scheme,
    run_cli,
    DEFAULT_GATEWAY_URL,
    _SessionInfo,
    _LocalWSBridge,
    _wait_for_port,
)


# ---------------------------------------------------------------------------
# DEFAULT_GATEWAY_URL
# ---------------------------------------------------------------------------
class DefaultGatewayTests(unittest.TestCase):
    def test_default_gateway_url_from_env(self) -> None:
        self.assertIsInstance(DEFAULT_GATEWAY_URL, str)
        self.assertTrue(DEFAULT_GATEWAY_URL.startswith("http"))

    def test_expose_uses_default_gateway(self) -> None:
        with mock.patch("godemo.client.Tunnel") as MockTunnel:
            instance = mock.MagicMock()
            instance.start.return_value = instance
            MockTunnel.return_value = instance
            expose(8000)
            MockTunnel.assert_called_once()
            call_kwargs = MockTunnel.call_args.kwargs
            self.assertEqual(call_kwargs["gateway_url"], DEFAULT_GATEWAY_URL)

    def test_default_gateway_url_env_override(self) -> None:
        import importlib
        from godemo import client as client_mod

        try:
            with mock.patch.dict(
                os.environ, {"GODEMO_GATEWAY_URL": "https://custom.example.com"}
            ):
                importlib.reload(client_mod)
                self.assertEqual(
                    client_mod.DEFAULT_GATEWAY_URL, "https://custom.example.com"
                )
        finally:
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("GODEMO_GATEWAY_URL", None)
                importlib.reload(client_mod)


# ---------------------------------------------------------------------------
# Tunnel construction and lifecycle
# ---------------------------------------------------------------------------
class TunnelConstructionTests(unittest.TestCase):
    def test_default_attributes(self) -> None:
        t = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        self.assertEqual(t.local_port, 8000)
        self.assertEqual(t.local_host, "127.0.0.1")
        self.assertEqual(t.gateway_url, "http://localhost:8080")
        self.assertEqual(t.request_timeout_seconds, 20.0)
        self.assertIsNone(t.public_url)
        self.assertIsNone(t.session_id)
        self.assertIsNone(t._token)

    def test_custom_attributes(self) -> None:
        t = Tunnel(
            local_port=3000,
            gateway_url="http://gw.test/",
            local_host="0.0.0.0",
            request_timeout_seconds=5.0,
        )
        self.assertEqual(t.local_port, 3000)
        self.assertEqual(t.local_host, "0.0.0.0")
        self.assertEqual(t.gateway_url, "http://gw.test")
        self.assertEqual(t.request_timeout_seconds, 5.0)

    def test_gateway_url_trailing_slash_stripped(self) -> None:
        t = Tunnel(local_port=8000, gateway_url="http://example.com///")
        self.assertEqual(t.gateway_url, "http://example.com")


class ExposeTests(unittest.TestCase):
    def test_expose_starts_tunnel(self) -> None:
        with mock.patch("godemo.client.Tunnel") as MockTunnel:
            instance = mock.MagicMock()
            instance.start.return_value = instance
            MockTunnel.return_value = instance
            result = expose(8000, gateway_url="http://localhost:8080")
            instance.start.assert_called_once()
            self.assertIs(result, instance)

    def test_expose_passes_custom_params(self) -> None:
        with mock.patch("godemo.client.Tunnel") as MockTunnel:
            instance = mock.MagicMock()
            instance.start.return_value = instance
            MockTunnel.return_value = instance
            expose(
                port=9000,
                gateway_url="http://custom.gw",
                local_host="0.0.0.0",
                request_timeout_seconds=5.0,
            )
            call_kwargs = MockTunnel.call_args.kwargs
            self.assertEqual(call_kwargs["local_port"], 9000)
            self.assertEqual(call_kwargs["gateway_url"], "http://custom.gw")
            self.assertEqual(call_kwargs["local_host"], "0.0.0.0")
            self.assertEqual(call_kwargs["request_timeout_seconds"], 5.0)

    def test_context_manager_closes_tunnel(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        with mock.patch.object(
            Tunnel, "start", autospec=True, side_effect=lambda self: self
        ):
            with mock.patch.object(Tunnel, "close", autospec=True) as close_mock:
                with tunnel as active:
                    self.assertIs(active, tunnel)
                close_mock.assert_called_once_with(tunnel)


class TunnelStartTests(unittest.TestCase):
    def test_start_already_alive_returns_self(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        mock_thread = mock.MagicMock()
        mock_thread.is_alive.return_value = True
        tunnel._thread = mock_thread
        result = tunnel.start()
        self.assertIs(result, tunnel)

    def test_start_raises_startup_error(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        tunnel._startup_error = RuntimeError("boom")
        tunnel._started.set()
        tunnel.public_url = None

        with mock.patch("threading.Thread") as MockThread:
            mock_t = mock.MagicMock()
            mock_t.is_alive.return_value = False
            MockThread.return_value = mock_t
            tunnel._thread = None
            tunnel._startup_error = RuntimeError("boom")
            tunnel._started.set()
            with self.assertRaises(RuntimeError):
                tunnel.start()

    def test_start_raises_if_no_public_url(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        tunnel._started.set()
        tunnel.public_url = None
        tunnel._startup_error = None

        with mock.patch("threading.Thread") as MockThread:
            mock_t = mock.MagicMock()
            mock_t.is_alive.return_value = False
            MockThread.return_value = mock_t
            tunnel._thread = None
            with self.assertRaises(RuntimeError):
                tunnel.start()

    def test_close_when_no_thread(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        tunnel.close()


# ---------------------------------------------------------------------------
# Async lifecycle
# ---------------------------------------------------------------------------
class AsyncLifecycleTests(unittest.TestCase):
    def test_delete_session_without_id_is_noop(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        asyncio.run(tunnel._delete_session())

    def test_delete_session_without_token_is_noop(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        tunnel.session_id = "ses_123"
        tunnel._token = None
        asyncio.run(tunnel._delete_session())

    def test_delete_session_handles_network_error(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://unreachable.invalid")
        tunnel.session_id = "ses_123"
        tunnel._token = "tok_abc"
        asyncio.run(tunnel._delete_session())


# ---------------------------------------------------------------------------
# ASGI Detection
# ---------------------------------------------------------------------------
class AsgiDetectionTests(unittest.TestCase):
    def test_fastapi_detected_as_asgi(self) -> None:
        class FakeApp:
            class __class__:
                __module__ = "fastapi.applications"

        fake = FakeApp()
        type(fake).__module__ = "fastapi.applications"
        self.assertTrue(_looks_like_asgi(fake))

    def test_starlette_detected_as_asgi(self) -> None:
        class FakeApp:
            pass

        fake = FakeApp()
        type(fake).__module__ = "starlette.applications"
        self.assertTrue(_looks_like_asgi(fake))

    def test_litestar_detected_as_asgi(self) -> None:
        class FakeApp:
            pass

        fake = FakeApp()
        type(fake).__module__ = "litestar.app"
        self.assertTrue(_looks_like_asgi(fake))

    def test_quart_detected_as_asgi(self) -> None:
        class FakeApp:
            pass

        fake = FakeApp()
        type(fake).__module__ = "quart.app"
        self.assertTrue(_looks_like_asgi(fake))

    def test_plain_callable_not_asgi(self) -> None:
        def handler(request):
            return None

        self.assertFalse(_looks_like_asgi(handler))

    def test_plain_async_function_detected_as_asgi(self) -> None:
        """Plain async functions with (scope, receive, send) are now correctly
        detected via iscoroutinefunction + param count check."""

        async def asgi_app(scope, receive, send):
            pass

        self.assertTrue(_looks_like_asgi(asgi_app))

    def test_two_param_callable_not_asgi(self) -> None:
        async def handler(scope, receive):
            pass

        self.assertFalse(_looks_like_asgi(handler))

    def test_class_with_asgi_call(self) -> None:
        class App:
            async def __call__(self, scope, receive, send):
                pass

        self.assertTrue(_looks_like_asgi(App()))

    def test_regular_module_not_asgi(self) -> None:
        class App:
            async def __call__(self, request):
                pass

        app = App()
        type(app).__module__ = "myapp.views"
        self.assertFalse(_looks_like_asgi(app))


# ---------------------------------------------------------------------------
# Scheme Fix Helpers
# ---------------------------------------------------------------------------
class FixWsSchemeTests(unittest.TestCase):
    def test_upgrades_ws_to_wss_when_gateway_is_https(self) -> None:
        result = _fix_ws_scheme("ws://gw.example.com/ws", "https://gw.example.com")
        self.assertEqual(result, "wss://gw.example.com/ws")

    def test_downgrades_wss_to_ws_when_gateway_is_http(self) -> None:
        result = _fix_ws_scheme("wss://gw.example.com/ws", "http://gw.example.com")
        self.assertEqual(result, "ws://gw.example.com/ws")

    def test_no_change_when_schemes_match(self) -> None:
        self.assertEqual(
            _fix_ws_scheme("wss://gw.example.com/ws", "https://gw.example.com"),
            "wss://gw.example.com/ws",
        )
        self.assertEqual(
            _fix_ws_scheme("ws://gw.example.com/ws", "http://gw.example.com"),
            "ws://gw.example.com/ws",
        )


class FixPublicSchemeTests(unittest.TestCase):
    def test_upgrades_http_to_https_when_gateway_is_https(self) -> None:
        result = _fix_public_scheme("http://sub.example.com", "https://gw.example.com")
        self.assertEqual(result, "https://sub.example.com")

    def test_no_change_when_already_https(self) -> None:
        result = _fix_public_scheme("https://sub.example.com", "https://gw.example.com")
        self.assertEqual(result, "https://sub.example.com")

    def test_no_change_when_gateway_is_http(self) -> None:
        result = _fix_public_scheme("http://sub.example.com", "http://gw.example.com")
        self.assertEqual(result, "http://sub.example.com")


# ---------------------------------------------------------------------------
# Machine Fingerprint
# ---------------------------------------------------------------------------
class FingerprintTests(unittest.TestCase):
    def test_fingerprint_is_hex_string(self) -> None:
        fp = _machine_fingerprint()
        self.assertEqual(len(fp), 64)
        int(fp, 16)

    def test_fingerprint_is_deterministic(self) -> None:
        fp1 = _machine_fingerprint()
        fp2 = _machine_fingerprint()
        self.assertEqual(fp1, fp2)


# ---------------------------------------------------------------------------
# SessionInfo dataclass
# ---------------------------------------------------------------------------
class SessionInfoTests(unittest.TestCase):
    def test_session_info_fields(self) -> None:
        info = _SessionInfo(
            session_id="ses_1",
            token="tok_1",
            public_url="https://dm-abc.example.com",
            ws_endpoint="wss://example.com/ws",
        )
        self.assertEqual(info.session_id, "ses_1")
        self.assertEqual(info.token, "tok_1")
        self.assertEqual(info.public_url, "https://dm-abc.example.com")
        self.assertEqual(info.ws_endpoint, "wss://example.com/ws")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class CliHelpTests(unittest.TestCase):
    def test_cli_help_exits_zero(self) -> None:
        with mock.patch("sys.argv", ["godemo-cli", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                run_cli()
            self.assertEqual(ctx.exception.code, 0)

    def test_cli_missing_port_exits_nonzero(self) -> None:
        with mock.patch("sys.argv", ["godemo-cli"]):
            with self.assertRaises(SystemExit) as ctx:
                run_cli()
            self.assertNotEqual(ctx.exception.code, 0)

    def test_cli_with_port_calls_expose(self) -> None:
        tunnel_mock = mock.MagicMock()
        tunnel_mock.public_url = "https://dm-test.example.com"

        with mock.patch(
            "sys.argv", ["godemo-cli", "3000", "--gateway", "http://test.gw"]
        ):
            with mock.patch(
                "godemo.client.expose", return_value=tunnel_mock
            ) as expose_mock:
                with mock.patch("signal.pause", side_effect=KeyboardInterrupt):
                    try:
                        run_cli()
                    except (KeyboardInterrupt, SystemExit):
                        pass
                expose_mock.assert_called_once_with(
                    port=3000,
                    gateway_url="http://test.gw",
                    local_host="127.0.0.1",
                    allowed_paths=None,
                )

    def test_cli_custom_host(self) -> None:
        tunnel_mock = mock.MagicMock()
        tunnel_mock.public_url = "https://dm-test.example.com"

        with mock.patch("sys.argv", ["godemo-cli", "8000", "--host", "0.0.0.0"]):
            with mock.patch(
                "godemo.client.expose", return_value=tunnel_mock
            ) as expose_mock:
                with mock.patch("signal.pause", side_effect=KeyboardInterrupt):
                    try:
                        run_cli()
                    except (KeyboardInterrupt, SystemExit):
                        pass
                expose_mock.assert_called_once_with(
                    port=8000,
                    gateway_url=None,
                    local_host="0.0.0.0",
                    allowed_paths=None,
                )

    def test_cli_with_allow_path(self) -> None:
        tunnel_mock = mock.MagicMock()
        tunnel_mock.public_url = "https://dm-test.example.com"

        with mock.patch(
            "sys.argv",
            ["godemo-cli", "3000", "--allow-path", "/api", "--allow-path", "/health"],
        ):
            with mock.patch(
                "godemo.client.expose", return_value=tunnel_mock
            ) as expose_mock:
                with mock.patch("signal.pause", side_effect=KeyboardInterrupt):
                    try:
                        run_cli()
                    except (KeyboardInterrupt, SystemExit):
                        pass
                expose_mock.assert_called_once_with(
                    port=3000,
                    gateway_url=None,
                    local_host="127.0.0.1",
                    allowed_paths=["/api", "/health"],
                )

    def test_cli_signal_pause_fallback(self) -> None:
        """When signal.pause() is unavailable (Windows), falls back to _stop_flag.wait()."""
        tunnel_mock = mock.MagicMock()
        tunnel_mock.public_url = "https://dm-test.example.com"
        tunnel_mock._stop_flag = mock.MagicMock()
        tunnel_mock._stop_flag.wait.side_effect = KeyboardInterrupt

        with mock.patch("sys.argv", ["godemo-cli", "3000"]):
            with mock.patch("godemo.client.expose", return_value=tunnel_mock):
                with mock.patch("signal.pause", side_effect=AttributeError):
                    try:
                        run_cli()
                    except (KeyboardInterrupt, SystemExit):
                        pass
                    tunnel_mock._stop_flag.wait.assert_called_once()


# ---------------------------------------------------------------------------
# share_app
# ---------------------------------------------------------------------------
class ExposeAppTests(unittest.TestCase):
    def test_share_app_asgi_starts_uvicorn(self) -> None:
        class FakeASGI:
            pass

        app = FakeASGI()
        type(app).__module__ = "fastapi.applications"

        with mock.patch("godemo.client._looks_like_asgi", return_value=True):
            with mock.patch("godemo.client.expose") as expose_mock:
                expose_mock.return_value = mock.MagicMock(public_url="http://test.url")
                with mock.patch("threading.Thread") as thread_mock:
                    thread_instance = mock.MagicMock()
                    thread_mock.return_value = thread_instance
                    with mock.patch("godemo.client._wait_for_port"):
                        share_app(app, gateway_url="http://gw.test")
                        thread_instance.start.assert_called_once()
                        expose_mock.assert_called_once()

    def test_share_app_wsgi_starts_werkzeug(self) -> None:
        def wsgi_app(environ, start_response):
            pass

        with mock.patch("godemo.client._looks_like_asgi", return_value=False):
            with mock.patch("godemo.client.expose") as expose_mock:
                expose_mock.return_value = mock.MagicMock(public_url="http://test.url")
                with mock.patch("threading.Thread") as thread_mock:
                    thread_instance = mock.MagicMock()
                    thread_mock.return_value = thread_instance
                    with mock.patch("godemo.client._wait_for_port"):
                        share_app(wsgi_app, gateway_url="http://gw.test")
                        thread_instance.start.assert_called_once()

    def test_share_app_picks_ephemeral_port(self) -> None:
        def wsgi_app(environ, start_response):
            pass

        with mock.patch("godemo.client._looks_like_asgi", return_value=False):
            with mock.patch("godemo.client.expose") as expose_mock:
                expose_mock.return_value = mock.MagicMock(public_url="http://test.url")
                with mock.patch("threading.Thread") as thread_mock:
                    thread_instance = mock.MagicMock()
                    thread_mock.return_value = thread_instance
                    with mock.patch("godemo.client._wait_for_port"):
                        share_app(wsgi_app, port=0, gateway_url="http://gw.test")
                        call_args = expose_mock.call_args
                        used_port = call_args.kwargs.get("port") or call_args[1].get(
                            "port"
                        )
                        self.assertGreater(used_port, 0)

    def test_share_app_with_explicit_port(self) -> None:
        def wsgi_app(environ, start_response):
            pass

        with mock.patch("godemo.client._looks_like_asgi", return_value=False):
            with mock.patch("godemo.client.expose") as expose_mock:
                expose_mock.return_value = mock.MagicMock(public_url="http://test.url")
                with mock.patch("threading.Thread") as thread_mock:
                    thread_instance = mock.MagicMock()
                    thread_mock.return_value = thread_instance
                    with mock.patch("godemo.client._wait_for_port"):
                        share_app(wsgi_app, port=9999, gateway_url="http://gw.test")
                        call_args = expose_mock.call_args
                        used_port = call_args.kwargs.get("port") or call_args[1].get(
                            "port"
                        )
                        self.assertEqual(used_port, 9999)


# ---------------------------------------------------------------------------
# Async handlers (unit-level)
# ---------------------------------------------------------------------------
class HandleWSDataTests(unittest.TestCase):
    def test_ws_data_unknown_connection_id_is_noop(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        msg = {"connection_id": "unknown", "data_b64": "", "opcode": "text"}
        asyncio.run(tunnel._handle_ws_data(msg, {}))

    def test_ws_close_unknown_connection_id_is_noop(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        msg = {"connection_id": "unknown"}
        asyncio.run(tunnel._handle_ws_close(msg, {}))


# ---------------------------------------------------------------------------
# LocalWSBridge
# ---------------------------------------------------------------------------
class LocalWSBridgeTests(unittest.TestCase):
    def test_bridge_creation(self) -> None:
        mock_ws = mock.MagicMock()
        bridge = _LocalWSBridge(mock_ws)
        self.assertIs(bridge.local_ws, mock_ws)
        self.assertFalse(bridge.closed.is_set())


# ---------------------------------------------------------------------------
# __init__.py exports
# ---------------------------------------------------------------------------
class PackageExportTests(unittest.TestCase):
    def test_top_level_imports(self) -> None:
        import godemo

        self.assertTrue(hasattr(godemo, "Tunnel"))
        self.assertTrue(hasattr(godemo, "expose"))
        self.assertTrue(hasattr(godemo, "share_app"))
        self.assertTrue(hasattr(godemo, "run_cli"))
        self.assertTrue(hasattr(godemo, "DEFAULT_GATEWAY_URL"))

    def test_all_exports(self) -> None:
        import godemo

        expected = {"Tunnel", "expose", "share_app", "run_cli", "DEFAULT_GATEWAY_URL"}
        self.assertEqual(set(godemo.__all__), expected)


# ---------------------------------------------------------------------------
# __main__.py
# ---------------------------------------------------------------------------
class MainModuleTests(unittest.TestCase):
    def test_main_calls_run_cli(self) -> None:
        with mock.patch("godemo.client.run_cli") as run_cli_mock:
            run_cli_mock.side_effect = SystemExit(0)
            with self.assertRaises(SystemExit):
                import godemo.__main__  # noqa: F401


# ---------------------------------------------------------------------------
# _handle_http_request (success path)
# ---------------------------------------------------------------------------
class HandleHTTPRequestTests(unittest.TestCase):
    def test_http_request_success_returns_response(self) -> None:
        tunnel = Tunnel(local_port=9999, gateway_url="http://gw.test")
        tunnel._ws_write_lock = asyncio.Lock()

        mock_ws = mock.AsyncMock()
        sent_messages: list[dict] = []
        mock_ws.send = mock.AsyncMock(side_effect=lambda m: sent_messages.append(m))

        import json
        import base64

        body_b64 = base64.b64encode(b"").decode()
        msg = {
            "type": "request",
            "request_id": "req_test",
            "method": "GET",
            "path": "/test",
            "query": "",
            "headers": {},
            "body_b64": body_b64,
        }

        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"ok":true}'
        mock_response.headers = mock.MagicMock()
        mock_response.headers.multi_items.return_value = [
            ("content-type", "application/json")
        ]

        with mock.patch("godemo.client.httpx.AsyncClient") as client_cls:
            client_instance = mock.AsyncMock()
            client_cls.return_value.__aenter__ = mock.AsyncMock(
                return_value=client_instance
            )
            client_cls.return_value.__aexit__ = mock.AsyncMock(return_value=False)
            client_instance.request.return_value = mock_response

            asyncio.run(tunnel._handle_http_request(mock_ws, msg))

        self.assertEqual(len(sent_messages), 1)
        parsed = json.loads(sent_messages[0])
        self.assertEqual(parsed["type"], "response")
        self.assertEqual(parsed["request_id"], "req_test")
        self.assertEqual(parsed["status"], 200)

    def test_http_request_error_returns_502(self) -> None:
        tunnel = Tunnel(local_port=9999, gateway_url="http://gw.test")
        tunnel._ws_write_lock = asyncio.Lock()

        mock_ws = mock.AsyncMock()
        sent_messages: list[dict] = []
        mock_ws.send = mock.AsyncMock(side_effect=lambda m: sent_messages.append(m))

        import json
        import base64

        msg = {
            "type": "request",
            "request_id": "req_err",
            "method": "GET",
            "path": "/fail",
            "query": "",
            "headers": {},
            "body_b64": base64.b64encode(b"").decode(),
        }

        with mock.patch("godemo.client.httpx.AsyncClient") as client_cls:
            client_instance = mock.AsyncMock()
            client_cls.return_value.__aenter__ = mock.AsyncMock(
                return_value=client_instance
            )
            client_cls.return_value.__aexit__ = mock.AsyncMock(return_value=False)
            client_instance.request.side_effect = ConnectionError("refused")

            asyncio.run(tunnel._handle_http_request(mock_ws, msg))

        self.assertEqual(len(sent_messages), 1)
        parsed = json.loads(sent_messages[0])
        self.assertEqual(parsed["type"], "response")
        self.assertEqual(parsed["status"], 502)


# ---------------------------------------------------------------------------
# _create_session
# ---------------------------------------------------------------------------
class CreateSessionTests(unittest.TestCase):
    def test_create_session_returns_session_info(self) -> None:
        tunnel = Tunnel(local_port=8080, gateway_url="http://gw.test")

        mock_resp = mock.MagicMock()
        mock_resp.status_code = 201
        mock_resp.raise_for_status = mock.MagicMock()
        mock_resp.json.return_value = {
            "session_id": "ses_abc",
            "token": "tok_xyz",
            "public_url": "http://dm-abc.localhost",
            "ws_endpoint": "ws://gw.test/api/v1/tunnel/ws?session_id=ses_abc",
        }

        with mock.patch("godemo.client.httpx.AsyncClient") as client_cls:
            client_instance = mock.AsyncMock()
            client_cls.return_value.__aenter__ = mock.AsyncMock(
                return_value=client_instance
            )
            client_cls.return_value.__aexit__ = mock.AsyncMock(return_value=False)
            client_instance.post.return_value = mock_resp

            session = asyncio.run(tunnel._create_session())

        self.assertEqual(session.session_id, "ses_abc")
        self.assertEqual(session.token, "tok_xyz")
        self.assertEqual(session.public_url, "http://dm-abc.localhost")

    def test_create_session_sends_allowed_paths(self) -> None:
        tunnel = Tunnel(
            local_port=8080,
            gateway_url="http://gw.test",
            allowed_paths=["/api", "/health"],
        )

        mock_resp = mock.MagicMock()
        mock_resp.status_code = 201
        mock_resp.raise_for_status = mock.MagicMock()
        mock_resp.json.return_value = {
            "session_id": "ses_wl",
            "token": "tok_wl",
            "public_url": "http://dm-wl.localhost",
            "ws_endpoint": "ws://gw.test/api/v1/tunnel/ws?session_id=ses_wl",
        }

        with mock.patch("godemo.client.httpx.AsyncClient") as client_cls:
            client_instance = mock.AsyncMock()
            client_cls.return_value.__aenter__ = mock.AsyncMock(
                return_value=client_instance
            )
            client_cls.return_value.__aexit__ = mock.AsyncMock(return_value=False)
            client_instance.post.return_value = mock_resp

            asyncio.run(tunnel._create_session())

        call_kwargs = client_instance.post.call_args
        sent_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        self.assertEqual(sent_json["allowed_paths"], ["/api", "/health"])

    def test_create_session_omits_allowed_paths_when_empty(self) -> None:
        tunnel = Tunnel(local_port=8080, gateway_url="http://gw.test")

        mock_resp = mock.MagicMock()
        mock_resp.status_code = 201
        mock_resp.raise_for_status = mock.MagicMock()
        mock_resp.json.return_value = {
            "session_id": "ses_no_wl",
            "token": "tok_no_wl",
            "public_url": "http://dm-no-wl.localhost",
            "ws_endpoint": "ws://gw.test/api/v1/tunnel/ws?session_id=ses_no_wl",
        }

        with mock.patch("godemo.client.httpx.AsyncClient") as client_cls:
            client_instance = mock.AsyncMock()
            client_cls.return_value.__aenter__ = mock.AsyncMock(
                return_value=client_instance
            )
            client_cls.return_value.__aexit__ = mock.AsyncMock(return_value=False)
            client_instance.post.return_value = mock_resp

            asyncio.run(tunnel._create_session())

        call_kwargs = client_instance.post.call_args
        sent_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        self.assertNotIn("allowed_paths", sent_json)


# ---------------------------------------------------------------------------
# _wait_for_port
# ---------------------------------------------------------------------------
class WaitForPortTests(unittest.TestCase):
    def test_wait_for_port_succeeds_on_listening_port(self) -> None:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        try:
            _wait_for_port("127.0.0.1", port, timeout=2.0)
        finally:
            sock.close()

    def test_wait_for_port_timeout_raises(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            _wait_for_port("127.0.0.1", 1, timeout=0.2)
        self.assertIn("did not start", str(ctx.exception))


# ---------------------------------------------------------------------------
# Event loop: malformed JSON and unknown message types
# ---------------------------------------------------------------------------
class EventLoopEdgeCaseTests(unittest.TestCase):
    def test_event_loop_handles_unknown_message_type(self) -> None:
        """Unknown message types should be silently ignored."""
        tunnel = Tunnel(local_port=9999, gateway_url="http://gw.test")
        tunnel._ws_write_lock = asyncio.Lock()
        tunnel._stop_flag.clear()

        import json

        mock_ws = mock.AsyncMock()
        messages = iter(
            [
                json.dumps({"type": "totally_unknown"}),
                asyncio.TimeoutError(),
            ]
        )

        async def fake_recv():
            msg = next(messages)
            if isinstance(msg, Exception):
                raise msg
            return msg

        mock_ws.recv = fake_recv

        async def run_loop():
            tunnel._stop_flag.set()
            await tunnel._event_loop(mock_ws)

        asyncio.run(run_loop())

    def test_event_loop_handles_binary_message(self) -> None:
        """Binary messages should be decoded to string."""
        tunnel = Tunnel(local_port=9999, gateway_url="http://gw.test")
        tunnel._ws_write_lock = asyncio.Lock()
        tunnel._stop_flag.clear()

        import json

        call_count = 0
        sent: list[str] = []
        mock_ws = mock.AsyncMock()

        async def fake_recv():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return json.dumps({"type": "ping"}).encode("utf-8")
            tunnel._stop_flag.set()
            raise asyncio.TimeoutError()

        async def fake_send(data: str) -> None:
            sent.append(data)

        mock_ws.recv = fake_recv
        mock_ws.send = fake_send

        asyncio.run(tunnel._event_loop(mock_ws))
        self.assertTrue(len(sent) > 0)
        parsed = json.loads(sent[0])
        self.assertEqual(parsed["type"], "pong")


class ReconnectTests(unittest.TestCase):
    def test_reconnect_on_ws_disconnect(self) -> None:
        """Verify _run reconnects after the WS connection drops."""
        tunnel = Tunnel(local_port=8080, gateway_url="http://gw.test")

        mock_session_resp = mock.MagicMock()
        mock_session_resp.status_code = 201
        mock_session_resp.raise_for_status = mock.MagicMock()
        mock_session_resp.json.return_value = {
            "session_id": "ses_rc",
            "token": "tok_rc",
            "public_url": "http://dm-rc.localhost",
            "ws_endpoint": "ws://gw.test/api/v1/tunnel/ws?session_id=ses_rc",
        }

        connect_count = 0

        class FakeWS:
            def __init__(self) -> None:
                self.sent: list[str] = []

            async def send(self, data: str) -> None:
                self.sent.append(data)

            async def recv(self) -> str:
                nonlocal connect_count
                if connect_count == 1:
                    raise websockets.ConnectionClosedError(None, None)
                # Second connection: wait until stop
                while not tunnel._stop_flag.is_set():
                    await asyncio.sleep(0.05)
                raise websockets.ConnectionClosedOK(None, None)

            async def close(self) -> None:
                pass

            async def __aenter__(self) -> "FakeWS":
                nonlocal connect_count
                connect_count += 1
                return self

            async def __aexit__(self, *args: object) -> None:
                pass

        with mock.patch("godemo.client.httpx.AsyncClient") as client_cls:
            client_instance = mock.AsyncMock()
            client_cls.return_value.__aenter__ = mock.AsyncMock(
                return_value=client_instance
            )
            client_cls.return_value.__aexit__ = mock.AsyncMock(return_value=False)
            client_instance.post.return_value = mock_session_resp
            client_instance.delete = mock.AsyncMock()

            with mock.patch("godemo.client.websockets.connect", return_value=FakeWS()):

                async def run_and_stop() -> None:
                    task = asyncio.create_task(tunnel._run())
                    # Wait for second connection
                    for _ in range(100):
                        if connect_count >= 2:
                            break
                        await asyncio.sleep(0.05)
                    tunnel._stop_flag.set()
                    await task

                asyncio.run(run_and_stop())

        self.assertGreaterEqual(
            connect_count, 2, "should have reconnected at least once"
        )

    def test_reconnect_stops_on_stop_flag(self) -> None:
        """Verify _run exits when stop_flag is set during backoff."""
        tunnel = Tunnel(local_port=8080, gateway_url="http://gw.test")

        mock_session_resp = mock.MagicMock()
        mock_session_resp.status_code = 201
        mock_session_resp.raise_for_status = mock.MagicMock()
        mock_session_resp.json.return_value = {
            "session_id": "ses_stop",
            "token": "tok_stop",
            "public_url": "http://dm-stop.localhost",
            "ws_endpoint": "ws://gw.test/api/v1/tunnel/ws?session_id=ses_stop",
        }

        connect_count = 0

        class FailingConnect:
            """Async context manager that always raises on __aenter__."""

            def __init__(self, *args: object, **kwargs: object) -> None:
                nonlocal connect_count
                connect_count += 1

            async def __aenter__(self) -> None:
                raise ConnectionRefusedError("connection refused")

            async def __aexit__(self, *args: object) -> None:
                pass

        with mock.patch("godemo.client.httpx.AsyncClient") as client_cls:
            client_instance = mock.AsyncMock()
            client_cls.return_value.__aenter__ = mock.AsyncMock(
                return_value=client_instance
            )
            client_cls.return_value.__aexit__ = mock.AsyncMock(return_value=False)
            client_instance.post.return_value = mock_session_resp
            client_instance.delete = mock.AsyncMock()

            with mock.patch(
                "godemo.client.websockets.connect", side_effect=FailingConnect
            ):

                async def run_and_stop() -> None:
                    task = asyncio.create_task(tunnel._run())
                    for _ in range(50):
                        if connect_count >= 2:
                            break
                        await asyncio.sleep(0.05)
                    tunnel._stop_flag.set()
                    await asyncio.wait_for(task, timeout=5)

                asyncio.run(run_and_stop())

        self.assertGreaterEqual(connect_count, 2)


if __name__ == "__main__":
    unittest.main()
