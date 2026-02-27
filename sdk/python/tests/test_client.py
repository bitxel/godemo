import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from demoit.client import (
    Tunnel,
    expose,
    expose_app,
    _looks_like_asgi,
    _machine_fingerprint,
    run_cli,
    DEFAULT_GATEWAY_URL,
    _SessionInfo,
    _LocalWSBridge,
)


# ---------------------------------------------------------------------------
# DEFAULT_GATEWAY_URL
# ---------------------------------------------------------------------------
class DefaultGatewayTests(unittest.TestCase):
    def test_default_gateway_url_from_env(self) -> None:
        self.assertIsInstance(DEFAULT_GATEWAY_URL, str)
        self.assertTrue(DEFAULT_GATEWAY_URL.startswith("http"))

    def test_expose_uses_default_gateway(self) -> None:
        with mock.patch("demoit.client.Tunnel") as MockTunnel:
            instance = mock.MagicMock()
            instance.start.return_value = instance
            MockTunnel.return_value = instance
            expose(8000)
            MockTunnel.assert_called_once()
            call_kwargs = MockTunnel.call_args.kwargs
            self.assertEqual(call_kwargs["gateway_url"], DEFAULT_GATEWAY_URL)

    def test_default_gateway_url_env_override(self) -> None:
        import importlib
        from demoit import client as client_mod
        original = client_mod.DEFAULT_GATEWAY_URL
        try:
            with mock.patch.dict(os.environ, {"DEMOIT_GATEWAY_URL": "https://custom.example.com"}):
                importlib.reload(client_mod)
                self.assertEqual(client_mod.DEFAULT_GATEWAY_URL, "https://custom.example.com")
        finally:
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DEMOIT_GATEWAY_URL", None)
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
        with mock.patch("demoit.client.Tunnel") as MockTunnel:
            instance = mock.MagicMock()
            instance.start.return_value = instance
            MockTunnel.return_value = instance
            result = expose(8000, gateway_url="http://localhost:8080")
            instance.start.assert_called_once()
            self.assertIs(result, instance)

    def test_expose_passes_custom_params(self) -> None:
        with mock.patch("demoit.client.Tunnel") as MockTunnel:
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
        with mock.patch.object(Tunnel, "start", autospec=True, side_effect=lambda self: self):
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
            public_url="https://qs-abc.example.com",
            ws_endpoint="wss://example.com/ws",
        )
        self.assertEqual(info.session_id, "ses_1")
        self.assertEqual(info.token, "tok_1")
        self.assertEqual(info.public_url, "https://qs-abc.example.com")
        self.assertEqual(info.ws_endpoint, "wss://example.com/ws")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class CliHelpTests(unittest.TestCase):
    def test_cli_help_exits_zero(self) -> None:
        with mock.patch("sys.argv", ["demoit", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                run_cli()
            self.assertEqual(ctx.exception.code, 0)

    def test_cli_missing_port_exits_nonzero(self) -> None:
        with mock.patch("sys.argv", ["demoit"]):
            with self.assertRaises(SystemExit) as ctx:
                run_cli()
            self.assertNotEqual(ctx.exception.code, 0)

    def test_cli_with_port_calls_expose(self) -> None:
        tunnel_mock = mock.MagicMock()
        tunnel_mock.public_url = "https://qs-test.example.com"

        with mock.patch("sys.argv", ["demoit", "3000", "--gateway", "http://test.gw"]):
            with mock.patch("demoit.client.expose", return_value=tunnel_mock) as expose_mock:
                with mock.patch("signal.pause", side_effect=KeyboardInterrupt):
                    try:
                        run_cli()
                    except (KeyboardInterrupt, SystemExit):
                        pass
                expose_mock.assert_called_once_with(
                    port=3000, gateway_url="http://test.gw", local_host="127.0.0.1"
                )

    def test_cli_custom_host(self) -> None:
        tunnel_mock = mock.MagicMock()
        tunnel_mock.public_url = "https://qs-test.example.com"

        with mock.patch("sys.argv", ["demoit", "8000", "--host", "0.0.0.0"]):
            with mock.patch("demoit.client.expose", return_value=tunnel_mock) as expose_mock:
                with mock.patch("signal.pause", side_effect=KeyboardInterrupt):
                    try:
                        run_cli()
                    except (KeyboardInterrupt, SystemExit):
                        pass
                expose_mock.assert_called_once_with(
                    port=8000, gateway_url=None, local_host="0.0.0.0"
                )


# ---------------------------------------------------------------------------
# expose_app
# ---------------------------------------------------------------------------
class ExposeAppTests(unittest.TestCase):
    def test_expose_app_asgi_starts_uvicorn(self) -> None:
        class FakeASGI:
            pass
        app = FakeASGI()
        type(app).__module__ = "fastapi.applications"

        with mock.patch("demoit.client._looks_like_asgi", return_value=True):
            with mock.patch("demoit.client.expose") as expose_mock:
                expose_mock.return_value = mock.MagicMock(public_url="http://test.url")
                with mock.patch("threading.Thread") as thread_mock:
                    thread_instance = mock.MagicMock()
                    thread_mock.return_value = thread_instance
                    with mock.patch("demoit.client._wait_for_port"):
                        result = expose_app(app, gateway_url="http://gw.test")
                        thread_instance.start.assert_called_once()
                        expose_mock.assert_called_once()

    def test_expose_app_wsgi_starts_werkzeug(self) -> None:
        def wsgi_app(environ, start_response):
            pass

        with mock.patch("demoit.client._looks_like_asgi", return_value=False):
            with mock.patch("demoit.client.expose") as expose_mock:
                expose_mock.return_value = mock.MagicMock(public_url="http://test.url")
                with mock.patch("threading.Thread") as thread_mock:
                    thread_instance = mock.MagicMock()
                    thread_mock.return_value = thread_instance
                    with mock.patch("demoit.client._wait_for_port"):
                        result = expose_app(wsgi_app, gateway_url="http://gw.test")
                        thread_instance.start.assert_called_once()

    def test_expose_app_picks_ephemeral_port(self) -> None:
        def wsgi_app(environ, start_response):
            pass

        with mock.patch("demoit.client._looks_like_asgi", return_value=False):
            with mock.patch("demoit.client.expose") as expose_mock:
                expose_mock.return_value = mock.MagicMock(public_url="http://test.url")
                with mock.patch("threading.Thread") as thread_mock:
                    thread_instance = mock.MagicMock()
                    thread_mock.return_value = thread_instance
                    with mock.patch("demoit.client._wait_for_port"):
                        result = expose_app(wsgi_app, port=0, gateway_url="http://gw.test")
                        call_args = expose_mock.call_args
                        used_port = call_args.kwargs.get("port") or call_args[1].get("port")
                        self.assertGreater(used_port, 0)

    def test_expose_app_with_explicit_port(self) -> None:
        def wsgi_app(environ, start_response):
            pass

        with mock.patch("demoit.client._looks_like_asgi", return_value=False):
            with mock.patch("demoit.client.expose") as expose_mock:
                expose_mock.return_value = mock.MagicMock(public_url="http://test.url")
                with mock.patch("threading.Thread") as thread_mock:
                    thread_instance = mock.MagicMock()
                    thread_mock.return_value = thread_instance
                    with mock.patch("demoit.client._wait_for_port"):
                        result = expose_app(wsgi_app, port=9999, gateway_url="http://gw.test")
                        call_args = expose_mock.call_args
                        used_port = call_args.kwargs.get("port") or call_args[1].get("port")
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
        import demoit
        self.assertTrue(hasattr(demoit, "Tunnel"))
        self.assertTrue(hasattr(demoit, "expose"))
        self.assertTrue(hasattr(demoit, "expose_app"))
        self.assertTrue(hasattr(demoit, "run_cli"))
        self.assertTrue(hasattr(demoit, "DEFAULT_GATEWAY_URL"))

    def test_all_exports(self) -> None:
        import demoit
        expected = {"Tunnel", "expose", "expose_app", "run_cli", "DEFAULT_GATEWAY_URL"}
        self.assertEqual(set(demoit.__all__), expected)


# ---------------------------------------------------------------------------
# __main__.py
# ---------------------------------------------------------------------------
class MainModuleTests(unittest.TestCase):
    def test_main_calls_run_cli(self) -> None:
        with mock.patch("demoit.client.run_cli") as run_cli_mock:
            run_cli_mock.side_effect = SystemExit(0)
            with self.assertRaises(SystemExit):
                import demoit.__main__


if __name__ == "__main__":
    unittest.main()
