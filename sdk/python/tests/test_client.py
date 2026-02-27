import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from demoit.client import Tunnel, expose, expose_app, _looks_like_asgi, run_cli, DEFAULT_GATEWAY_URL


class DefaultGatewayTests(unittest.TestCase):
    def test_default_gateway_url_from_env(self) -> None:
        self.assertIsInstance(DEFAULT_GATEWAY_URL, str)
        self.assertTrue(DEFAULT_GATEWAY_URL.startswith("http"))

    def test_expose_uses_default_gateway(self) -> None:
        with mock.patch.object(Tunnel, "start", autospec=True, return_value="started"):
            expose(8000)


class ExposeTests(unittest.TestCase):
    def test_expose_starts_tunnel(self) -> None:
        with mock.patch.object(Tunnel, "start", autospec=True, return_value="started") as start_mock:
            result = expose(8000, gateway_url="http://localhost:8080")
            self.assertEqual(result, "started")
            start_mock.assert_called_once()

    def test_context_manager_closes_tunnel(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        with mock.patch.object(Tunnel, "start", autospec=True, side_effect=lambda self: self):
            with mock.patch.object(Tunnel, "close", autospec=True) as close_mock:
                with tunnel as active:
                    self.assertIs(active, tunnel)
                close_mock.assert_called_once_with(tunnel)


class AsyncLifecycleTests(unittest.TestCase):
    def test_delete_session_without_id_is_noop(self) -> None:
        tunnel = Tunnel(local_port=8000, gateway_url="http://localhost:8080")
        asyncio.run(tunnel._delete_session())


class AsgiDetectionTests(unittest.TestCase):
    def test_fastapi_detected_as_asgi(self) -> None:
        class FakeApp:
            class __class__:
                __module__ = "fastapi.applications"
        fake = FakeApp()
        type(fake).__module__ = "fastapi.applications"
        self.assertTrue(_looks_like_asgi(fake))

    def test_plain_callable_not_asgi(self) -> None:
        def handler(request):
            return None
        self.assertFalse(_looks_like_asgi(handler))


class CliHelpTests(unittest.TestCase):
    def test_cli_help_exits_zero(self) -> None:
        with mock.patch("sys.argv", ["demoit", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                run_cli()
            self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
