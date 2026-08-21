from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

DEFAULT_METRICS_PATH = "/metrics"
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_BYTES = 16 * 1024 * 1024


class MetricsClientError(Exception):
    retryable = False


class AuthenticationError(MetricsClientError):
    retryable = False


class SourceContractError(MetricsClientError):
    retryable = False


class PayloadTooLargeError(SourceContractError):
    retryable = False


class TransientMetricsError(MetricsClientError):
    retryable = True


class RateLimitedError(TransientMetricsError):
    def __init__(self, retry_after_seconds: float | None) -> None:
        super().__init__(
            f"rate limited by source; retry_after_seconds={retry_after_seconds}"
        )
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True)
class MetricsClientConfig:
    base_url: str
    api_key: str | None = field(default=None, repr=False)
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)
    allow_anonymous: bool = False
    allow_insecure_transport: bool = False
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_bytes: int = DEFAULT_MAX_BYTES

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("https", "http") or parsed.netloc == "":
            raise ValueError("base_url must be an absolute http(s) URL")
        if parsed.scheme == "http" and not self.allow_insecure_transport:
            raise ValueError(
                "plain http requires allow_insecure_transport=true"
            )

        has_api_key = bool(self.api_key)
        has_username = bool(self.username)
        has_password = bool(self.password)
        if has_api_key and (has_username or has_password):
            raise ValueError("api_key mode excludes username/password credentials")
        if has_username != has_password:
            raise ValueError("credentials mode requires both username and password")
        if not (has_api_key or (has_username and has_password) or self.allow_anonymous):
            raise ValueError(
                "no credentials configured; set allow_anonymous explicitly to accept unauthenticated /metrics"
            )
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")

    @property
    def auth_mode(self) -> str:
        if self.api_key:
            return "api_key"
        if self.username and self.password:
            return "credentials"
        return "anonymous"

    def redacted_view(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "auth_mode": self.auth_mode,
            "allow_anonymous": self.allow_anonymous,
            "allow_insecure_transport": self.allow_insecure_transport,
            "timeout_seconds": self.timeout_seconds,
            "max_bytes": self.max_bytes,
        }

    def metrics_url(self) -> str:
        return self.base_url.rstrip("/") + DEFAULT_METRICS_PATH

    def _basic_auth(self) -> httpx.BasicAuth | None:
        mode = self.auth_mode
        if mode == "api_key":
            return httpx.BasicAuth(username="", password=self.api_key or "")
        if mode == "credentials":
            return httpx.BasicAuth(username=self.username or "", password=self.password or "")
        return None


@dataclass(frozen=True)
class FetchResult:
    text: str
    status_code: int
    content_type: str
    byte_size: int
    duration_ms: int


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return seconds if seconds > 0 else None


class MetricsClient:
    def __init__(
        self,
        config: MetricsClientConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._client: httpx.Client | None = None

    def __enter__(self) -> "MetricsClient":
        self._ensure_client()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                auth=self._config._basic_auth(),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                transport=self._transport,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def fetch_metrics(self) -> FetchResult:
        client = self._ensure_client()
        url = self._config.metrics_url()
        started = time.perf_counter()
        try:
            with client.stream("GET", url) as response:
                status = response.status_code
                if status != 200:
                    self._raise_for_status(status, response.headers)
                content_length = response.headers.get("content-length")
                if content_length is not None and content_length.isdigit():
                    if int(content_length) > self._config.max_bytes:
                        raise PayloadTooLargeError(
                            f"/metrics snapshot declares {content_length} bytes, limit is {self._config.max_bytes}"
                        )
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > self._config.max_bytes:
                        raise PayloadTooLargeError(
                            f"/metrics snapshot exceeded {self._config.max_bytes} bytes while streaming"
                        )
                    chunks.append(chunk)
        except httpx.TransportError as exc:
            raise TransientMetricsError(f"transport failure fetching {url}: {exc}") from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        body = b"".join(chunks).decode("utf-8")
        return FetchResult(
            text=body,
            status_code=status,
            content_type=response.headers.get("content-type", ""),
            byte_size=len(body.encode("utf-8")),
            duration_ms=duration_ms,
        )

    def _raise_for_status(self, status: int, headers: httpx.Headers) -> None:
        if status in (401, 403):
            raise AuthenticationError(
                f"source rejected credentials for /metrics with HTTP {status}"
            )
        if status == 429:
            raise RateLimitedError(_parse_retry_after(headers.get("retry-after")))
        if 500 <= status <= 599:
            raise TransientMetricsError(f"source returned HTTP {status} for /metrics")
        if status == 408:
            raise TransientMetricsError("source returned HTTP 408 request timeout")
        raise SourceContractError(f"unexpected HTTP {status} from /metrics")


__all__ = [
    "AuthenticationError",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_METRICS_PATH",
    "DEFAULT_TIMEOUT_SECONDS",
    "FetchResult",
    "MetricsClient",
    "MetricsClientConfig",
    "MetricsClientError",
    "PayloadTooLargeError",
    "RateLimitedError",
    "SourceContractError",
    "TransientMetricsError",
]
