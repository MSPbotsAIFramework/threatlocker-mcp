# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Async client for the ThreatLocker Portal API."""

import asyncio
import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

import httpx

from ._json import error_envelope
from .config import API_URL_TEMPLATE, PORTAL_INSTANCES, PROBE_PATH

logger = logging.getLogger("threatlocker_mcp.api")

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_PROBE_TIMEOUT = httpx.Timeout(8.0)
_MAX_RETRIES = 2
_MAX_BACKOFF_SECONDS = 20.0
# Whole-call budget including retries; the gateway times a tool call out at 120s.
_CALL_BUDGET_SECONDS = 100.0

# One connection pool for the process. It never holds credentials: the
# Authorization header is built per request from the caller's own key, so
# sharing the pool across tenants is safe.
_shared_http_client: httpx.AsyncClient | None = None


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _shared_http_client


# Which portal instance a key works on (sha256 of the key -> (instance letter,
# monotonic expiry time)). Holds no credential and nothing that can be turned
# back into one; it only saves re-probing every instance on each request.
# Entries expire so a key moved to another instance is re-probed.
_instance_cache: "OrderedDict[str, tuple[str, float]]" = OrderedDict()
_INSTANCE_CACHE_SIZE = 500
_INSTANCE_CACHE_TTL_SECONDS = 24 * 60 * 60.0


def _cache_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def clear_instance_cache() -> None:
    _instance_cache.clear()


# status_code -> (error code, retryable). 0 means no HTTP response at all
# (connection error or timeout).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    417: ("invalid_argument", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
    # The Portal API answers an invalid or expired key with a non-standard 440.
    440: ("unauthorized", False),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class ThreatLockerError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"ThreatLocker API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class ThreatLockerCredentials:
    api_key: str
    organization_id: str | None = None
    instance: str | None = None
    # Set when a header value is malformed: tools then return invalid_argument
    # instead of calling ThreatLocker, while tools/list still works.
    header_error: str | None = None

    def __repr__(self) -> str:  # never leak the key into logs or tracebacks
        return (
            f"ThreatLockerCredentials(organization_id={self.organization_id!r}, instance={self.instance!r}, "
            "api_key=<redacted>)"
        )


@dataclass
class Page:
    data: Any
    pagination: dict | None


class ThreatLockerClient:
    """Portal API wrapper for one caller's API key and managed organization."""

    def __init__(self, credentials: ThreatLockerCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self.header_error = credentials.header_error
        self.instance = credentials.instance

    def _client(self) -> httpx.AsyncClient:
        return self._http or _get_shared_http_client()

    def _headers(self) -> dict[str, str]:
        # The Portal API takes the raw key, without a "Bearer" prefix.
        headers = {"Authorization": self._credentials.api_key, "Accept": "application/json"}
        if self._credentials.organization_id:
            headers["ManagedOrganizationId"] = self._credentials.organization_id
        return headers

    async def resolve_instance(self) -> str:
        if self.instance:
            return self.instance
        key = _cache_key(self._credentials.api_key)
        cached = _instance_cache.get(key)
        if cached and time.monotonic() < cached[1]:
            self.instance = cached[0]
            return cached[0]

        async def probe(instance: str) -> str | None:
            url = f"{API_URL_TEMPLATE.format(instance=instance)}/{PROBE_PATH}"
            try:
                resp = await self._client().get(url, headers=self._headers(), timeout=_PROBE_TIMEOUT)
            except httpx.RequestError:
                return None
            return instance if resp.is_success else None

        results = await asyncio.gather(*(probe(i) for i in PORTAL_INSTANCES))
        found = next((r for r in results if r), None)
        if not found:
            raise ThreatLockerError(
                401,
                "No ThreatLocker portal instance accepted this API key and organization id. Check both, or send "
                "X-Threatlocker-Instance (the letter in your portal address, e.g. g for portal.g.threatlocker.com).",
            )
        _instance_cache[key] = (found, time.monotonic() + _INSTANCE_CACHE_TTL_SECONDS)
        _instance_cache.move_to_end(key)
        while len(_instance_cache) > _INSTANCE_CACHE_SIZE:
            _instance_cache.popitem(last=False)
        self.instance = found
        logger.info("threatlocker_api detected instance=%s", found)
        return found

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return (await self.request("GET", path, params=params)).data

    async def post(self, path: str, body: Any, headers: dict[str, str] | None = None) -> Page:
        return await self.request("POST", path, body=body, headers=headers)

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> Page:
        instance = await self.resolve_instance()
        url = f"{API_URL_TEMPLATE.format(instance=instance)}/{path.strip('/')}"
        query = {k: _param_value(v) for k, v in (params or {}).items() if v is not None}
        all_headers = self._headers() | (headers or {})
        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            resp: httpx.Response | None = None
            error: ThreatLockerError | None = None
            try:
                resp = await self._client().request(method, url, params=query, json=body, headers=all_headers)
                status = resp.status_code
            except httpx.TimeoutException:
                status, error = 0, ThreatLockerError(0, f"Timed out calling ThreatLocker ({method} {path})")
            except httpx.RequestError as e:
                status = 0
                error = ThreatLockerError(0, f"Network error calling ThreatLocker ({method} {path}): {type(e).__name__}")

            logger.info(
                "threatlocker_api method=%s path=%s status=%s ms=%d attempt=%d",
                method, path, status, (time.monotonic() - t0) * 1000, attempt,
            )

            # Every call this server makes is a read (searches are POSTs with a
            # filter body), so all of them may be retried.
            retryable = status in (0, 429) or status >= 500
            if retryable and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue
            if error is not None:
                raise error
            assert resp is not None
            if resp.status_code >= 400:
                raise ThreatLockerError(resp.status_code, _error_message(resp, path))
            return Page(_parse_body(resp), _pagination(resp))


def _param_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _pagination(resp: httpx.Response) -> dict | None:
    raw = resp.headers.get("pagination")
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _parse_body(resp: httpx.Response) -> Any:
    if not resp.content or not resp.content.strip():
        return None
    try:
        return resp.json()
    except ValueError:
        return {"raw_response": resp.text[:2000]}


def _error_message(resp: httpx.Response, path: str) -> str:
    fallback = f"ThreatLocker returned HTTP {resp.status_code} for {path}"
    try:
        payload = resp.json()
    except ValueError:
        text = resp.text.strip()
        return f"{fallback}: {text[:300]}" if text else fallback
    if isinstance(payload, str) and payload:
        return f"{fallback}: {payload[:300]}"
    if isinstance(payload, dict):
        for key in ("message", "Message", "title", "error", "detail"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                errors = payload.get("errors")
                extra = f" ({json.dumps(errors)[:300]})" if isinstance(errors, dict) and errors else ""
                return f"{fallback}: {value[:300]}{extra}"
    return fallback
