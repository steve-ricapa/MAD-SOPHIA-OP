from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from typing import Callable

import httpx

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.connectors.uptime_kuma.client import (
    AuthenticationError,
    MetricsClient,
    MetricsClientConfig,
    PayloadTooLargeError,
    RateLimitedError,
    SourceContractError,
    TransientMetricsError,
)
from txdx_etl.connectors.uptime_kuma.parser import parse_metrics

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "connectors" / "uptime_kuma"
BASE_URL = "https://kuma.example.test"


def load_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class ClientTestBase(unittest.TestCase):
    def make_client(
        self,
        config: MetricsClientConfig,
        responder: Callable[[httpx.Request], httpx.Response],
    ) -> tuple[MetricsClient, dict]:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["request"] = request
            return responder(request)

        return MetricsClient(config, transport=httpx.MockTransport(handler)), captured

    def api_key_config(self, **overrides) -> MetricsClientConfig:
        defaults = {
            "base_url": BASE_URL,
            "api_key": "kuma-key-123",
        }
        defaults.update(overrides)
        return MetricsClientConfig(**defaults)


class ConfigValidationTests(ClientTestBase):
    def test_plain_http_requires_explicit_insecure_flag(self) -> None:
        with self.assertRaises(ValueError):
            self.api_key_config(base_url="http://kuma.example.test")

    def test_plain_http_allowed_when_explicit(self) -> None:
        config = self.api_key_config(
            base_url="http://kuma.internal", allow_insecure_transport=True
        )
        self.assertEqual(config.metrics_url(), "http://kuma.internal/metrics")

    def test_relative_or_invalid_url_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.api_key_config(base_url="kuma.example.test")

    def test_anonymous_requires_explicit_flag(self) -> None:
        with self.assertRaises(ValueError):
            MetricsClientConfig(base_url=BASE_URL)

    def test_explicit_anonymous_is_accepted(self) -> None:
        config = MetricsClientConfig(base_url=BASE_URL, allow_anonymous=True)
        self.assertEqual(config.auth_mode, "anonymous")

    def test_api_key_excludes_username_password(self) -> None:
        with self.assertRaises(ValueError):
            self.api_key_config(username="admin", password="secret")

    def test_credentials_require_both_parts(self) -> None:
        with self.assertRaises(ValueError):
            MetricsClientConfig(base_url=BASE_URL, username="admin")

    def test_redacted_view_never_contains_secrets(self) -> None:
        view = self.api_key_config(username=None, password=None).redacted_view()
        self.assertNotIn("kuma-key-123", str(view))
        self.assertEqual(view["auth_mode"], "api_key")
        self.assertEqual(view["base_url"], BASE_URL)


class AuthHeaderTests(ClientTestBase):
    @staticmethod
    def _decode_basic(request: httpx.Request) -> str:
        header = request.headers["Authorization"]
        scheme, encoded = header.split(" ", 1)
        assert scheme == "Basic"
        return base64.b64decode(encoded).decode("utf-8")

    def test_api_key_sent_as_password_with_empty_username(self) -> None:
        client, captured = self.make_client(
            self.api_key_config(),
            lambda request: httpx.Response(200, text="# empty\n"),
        )
        with client:
            client.fetch_metrics()
        request = captured["request"]
        self.assertEqual(request.url, f"{BASE_URL}/metrics")
        self.assertEqual(self._decode_basic(request), ":kuma-key-123")

    def test_credentials_mode_uses_given_username_and_password(self) -> None:
        config = MetricsClientConfig(
            base_url=BASE_URL, username="admin", password="s3cret"
        )
        client, captured = self.make_client(
            config,
            lambda request: httpx.Response(200, text="# empty\n"),
        )
        with client:
            client.fetch_metrics()
        self.assertEqual(self._decode_basic(captured["request"]), "admin:s3cret")

    def test_anonymous_mode_sends_no_authorization_header(self) -> None:
        config = MetricsClientConfig(base_url=BASE_URL, allow_anonymous=True)
        client, captured = self.make_client(
            config,
            lambda request: httpx.Response(200, text="# empty\n"),
        )
        with client:
            client.fetch_metrics()
        self.assertNotIn("Authorization", captured["request"].headers)


class FetchClassificationTests(ClientTestBase):
    def fetch(self, responder, config: MetricsClientConfig | None = None):
        client, captured = self.make_client(config or self.api_key_config(), responder)
        with client:
            return client.fetch_metrics(), captured

    def test_success_result_metadata_and_parsable_body(self) -> None:
        fixture = load_text("metrics-v2.txt")
        result, captured = self.fetch(
            lambda request: httpx.Response(200, text=fixture)
        )
        snapshot = parse_metrics(result.text)
        self.assertEqual(snapshot.capabilities.monitor_count, 2)
        self.assertEqual(result.status_code, 200)
        self.assertIn("text/plain", result.content_type)
        self.assertGreaterEqual(result.duration_ms, 0)

    def test_unauthorized_blocks_configuration(self) -> None:
        with self.assertRaises(AuthenticationError) as ctx:
            self.fetch(lambda request: httpx.Response(401, text="unauthorized"))
        self.assertFalse(ctx.exception.retryable)

    def test_forbidden_blocks_configuration(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.fetch(lambda request: httpx.Response(403, text="forbidden"))

    def test_rate_limit_is_retryable_with_numeric_retry_after(self) -> None:
        with self.assertRaises(RateLimitedError) as ctx:
            self.fetch(
                lambda request: httpx.Response(
                    429, text="slow down", headers={"Retry-After": "30"}
                )
            )
        self.assertTrue(ctx.exception.retryable)
        self.assertEqual(ctx.exception.retry_after_seconds, 30.0)

    def test_rate_limit_with_http_date_retry_after_yields_none(self) -> None:
        with self.assertRaises(RateLimitedError) as ctx:
            self.fetch(
                lambda request: httpx.Response(
                    429,
                    text="slow down",
                    headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"},
                )
            )
        self.assertIsNone(ctx.exception.retry_after_seconds)

    def test_server_errors_are_transient(self) -> None:
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                with self.assertRaises(TransientMetricsError):
                    self.fetch(lambda request: httpx.Response(status, text="oops"))

    def test_request_timeout_maps_to_transient_error(self) -> None:
        def responder(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("connect timed out", request=request)

        with self.assertRaises(TransientMetricsError):
            self.fetch(responder)

    def test_unexpected_status_is_contract_error(self) -> None:
        with self.assertRaises(SourceContractError):
            self.fetch(lambda request: httpx.Response(404, text="missing"))


class PayloadLimitTests(ClientTestBase):
    def test_content_length_over_limit_rejected_before_reading(self) -> None:
        big = "x" * (20 * 1024 * 1024)
        config = self.api_key_config(max_bytes=1024)
        client, _ = self.make_client(
            config,
            lambda request: httpx.Response(
                200, text=big, headers={"Content-Length": str(len(big))}
            ),
        )
        with client, self.assertRaises(PayloadTooLargeError):
            client.fetch_metrics()

    def test_streamed_body_over_limit_aborts_read(self) -> None:
        fixture = load_text("metrics-v2.txt")
        config = self.api_key_config(max_bytes=len(fixture) // 2)
        client, _ = self.make_client(
            config,
            lambda request: httpx.Response(200, text=fixture),
        )
        with client, self.assertRaises(PayloadTooLargeError):
            client.fetch_metrics()

    def test_body_at_limit_is_accepted(self) -> None:
        fixture = load_text("metrics-v123.txt")
        config = self.api_key_config(max_bytes=len(fixture.encode("utf-8")))
        client, _ = self.make_client(
            config,
            lambda request: httpx.Response(200, text=fixture),
        )
        with client:
            result = client.fetch_metrics()
        self.assertEqual(result.byte_size, len(fixture.encode("utf-8")))


if __name__ == "__main__":
    unittest.main()
