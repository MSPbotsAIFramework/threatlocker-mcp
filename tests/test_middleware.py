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
"""Credential middleware: 401/400 on bad headers, per-request isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from threatlocker_mcp.__main__ import build_http_app
from threatlocker_mcp.server import (
    GatewayCredentialsMiddleware,
    _credentials_var,
    create_mcp_server,
    get_client_from_context,
    normalize_instance,
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
ORG = "00000000-0000-0000-0000-000000000000"
CREDS = {"X-Threatlocker-Api-Key": "your-api-key", "X-Threatlocker-Organization-Id": ORG}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize("value", [None, "", "${THREATLOCKER_API_KEY}"])
def test_missing_key_returns_401(value):
    headers = MCP_HEADERS | {"X-Threatlocker-Organization-Id": ORG}
    if value is not None:
        headers["X-Threatlocker-Api-Key"] = value
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=headers)
    assert resp.status_code == 401
    assert "X-Threatlocker-Api-Key" in resp.json()["required_headers"]


@pytest.mark.parametrize(
    "extra",
    [{"X-Threatlocker-Organization-Id": "acme"}, {"X-Threatlocker-Instance": "g1!"}],
)
def test_bad_values_return_400(extra):
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS | extra)
    assert resp.status_code == 400


def test_tools_list_over_http():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS)
    assert resp.status_code == 200
    for name in ("threatlocker_navigate", "threatlocker_computers_list", "threatlocker_audit_search"):
        assert name in resp.text


@pytest.mark.parametrize(
    "value,expected",
    [
        ("g", "g"),
        ("G", "g"),
        ("portal.h.threatlocker.com", "h"),
        ("https://portalapi.c.threatlocker.com/portalapi", "c"),
        ("https://betaportalapi.g.threatlocker.com", "g"),
        ("g.example", None),
    ],
)
def test_normalize_instance(value, expected):
    assert normalize_instance(value) == expected


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


def test_headers_reach_request_context_and_are_reset():
    seen = _run_middleware(
        [
            (b"x-threatlocker-api-key", b" key-123 "),
            (b"x-threatlocker-organization-id", ORG.encode()),
            (b"x-threatlocker-instance", b"G"),
        ]
    )
    creds = seen["credentials"]
    assert (creds.api_key, creds.organization_id, creds.instance) == ("key-123", ORG, "g")
    assert seen["client"].instance == "g"
    assert _credentials_var.get() is None


def test_organization_and_instance_are_optional():
    seen = _run_middleware([(b"x-threatlocker-api-key", b"key-123")])
    assert seen["credentials"].organization_id is None
    assert seen["credentials"].instance is None


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().api_key
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().api_key))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(key: bytes) -> dict:
        return {"type": "http", "path": "/mcp", "headers": [(b"x-threatlocker-api-key", key)]}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), receive, send), middleware(scope(b"tenant-b"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_key():
    seen = _run_middleware([(b"x-threatlocker-api-key", b"very-secret-key")])
    assert "very-secret-key" not in repr(seen["credentials"])
