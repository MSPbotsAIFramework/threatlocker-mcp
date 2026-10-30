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
"""Ringfencing: read a policy, check eligibility, opt in (PRD-21247).

Mocked httpx, no network access needed -- same Recorder/_call pattern as
test_api_client.py.
"""

import json

import httpx
import pytest

from threatlocker_mcp import api_client
from threatlocker_mcp.api_client import ThreatLockerCredentials
from threatlocker_mcp.server import _credentials_var, create_mcp_server

ORG_A = "11111111-2222-3333-4444-555555555555"
ORG_B = "66666666-7777-8888-9999-000000000000"
CREDS = ThreatLockerCredentials(api_key="key-123", organization_id=ORG_A, instance="g")
POLICY_ID = "cccccccc-dddd-eeee-ffff-000000000000"


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)
    api_client.clear_instance_cache()


class Recorder:
    """Mock transport: replies by "METHOD path" or path below /portalapi/."""

    def __init__(self, routes=None, default=None):
        self.requests: list[httpx.Request] = []
        self.routes = routes or {}
        self.default = default if default is not None else []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix("/portalapi/")
        reply = self.routes.get(f"{request.method} {path}", self.routes.get(path, self.default))
        if callable(reply):
            return reply(request)
        return httpx.Response(200, json=reply)


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict, credentials: ThreatLockerCredentials = CREDS):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(credentials)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


# ---- get -----------------------------------------------------------------------


async def test_get_known_policy_returns_data(monkeypatch):
    policy = {"ringfencePolicyId": POLICY_ID, "name": "Default Policy"}
    rec = Recorder({f"GET RingfencePolicy/{POLICY_ID}": policy})
    result = await _call(monkeypatch, rec, "threatlocker_ringfence_get", {"ringfencePolicyId": POLICY_ID})
    assert result == policy
    assert rec.requests[0].url.path == f"/portalapi/RingfencePolicy/{POLICY_ID}"


async def test_get_unknown_policy_returns_not_found(monkeypatch):
    rec = Recorder(default=lambda r: httpx.Response(404, json={"message": "Policy not found"}))
    result = await _call(monkeypatch, rec, "threatlocker_ringfence_get", {"ringfencePolicyId": POLICY_ID})
    assert result["error"]["code"] == "not_found"


async def test_get_malformed_id_never_calls_api(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "threatlocker_ringfence_get", {"ringfencePolicyId": "not-a-guid"})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


# ---- eligibility -----------------------------------------------------------------


async def test_eligibility_returns_result(monkeypatch):
    rec = Recorder({"POST RingfencePolicy/Eligibility": {"eligible": True}})
    result = await _call(monkeypatch, rec, "threatlocker_ringfence_eligibility", {})
    assert result == {"eligible": True}
    assert rec.requests[0].content == b""


# ---- opt in --------------------------------------------------------------------


async def test_opt_in_returns_success(monkeypatch):
    rec = Recorder({"POST RingfencePolicy/OptIn": {}})
    result = await _call(monkeypatch, rec, "threatlocker_ringfence_opt_in", {})
    assert result == {"action": "opt_in", "result": {}}
    assert rec.requests[0].content == b""


async def test_opt_in_transient_failure_is_not_retried(monkeypatch):
    # PRD-21247 review round 1: opt_in calls client.post(..., idempotent=False) -- a transient
    # 503 on the write itself must surface as a failure instead of being silently resent.
    rec = Recorder({"POST RingfencePolicy/OptIn": lambda r: httpx.Response(503)})
    result = await _call(monkeypatch, rec, "threatlocker_ringfence_opt_in", {})
    assert result["error"]["code"] == "upstream_error"
    assert len(rec.requests) == 1


# ---- shared across the 3 new ringfencing tools ---------------------------------


@pytest.mark.parametrize(
    "tool,args",
    [
        ("threatlocker_ringfence_get", {"ringfencePolicyId": POLICY_ID}),
        ("threatlocker_ringfence_eligibility", {}),
        ("threatlocker_ringfence_opt_in", {}),
    ],
)
async def test_new_tools_without_credentials_return_not_configured(monkeypatch, tool, args):
    content, _ = await create_mcp_server().call_tool(tool, args)
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"


@pytest.mark.parametrize(
    "tool,args",
    [
        ("threatlocker_ringfence_get", {"ringfencePolicyId": POLICY_ID}),
        ("threatlocker_ringfence_eligibility", {}),
        ("threatlocker_ringfence_opt_in", {}),
    ],
)
async def test_two_organizations_never_cross_managed_organization_id(monkeypatch, tool, args):
    rec = Recorder(
        {
            f"GET RingfencePolicy/{POLICY_ID}": {"ringfencePolicyId": POLICY_ID},
            "POST RingfencePolicy/Eligibility": {"eligible": True},
            "POST RingfencePolicy/OptIn": {},
        }
    )
    creds_a = ThreatLockerCredentials(api_key="key-123", organization_id=ORG_A, instance="g")
    creds_b = ThreatLockerCredentials(api_key="key-456", organization_id=ORG_B, instance="g")
    await _call(monkeypatch, rec, tool, args, creds_a)
    await _call(monkeypatch, rec, tool, args, creds_b)
    org_ids = [r.headers.get("ManagedOrganizationId") for r in rec.requests]
    assert org_ids == [ORG_A, ORG_B]


async def test_success_results_name_id_and_action(monkeypatch):
    rec = Recorder(
        {
            f"GET RingfencePolicy/{POLICY_ID}": {"ringfencePolicyId": POLICY_ID, "name": "Default"},
            "POST RingfencePolicy/Eligibility": {"eligible": True},
            "POST RingfencePolicy/OptIn": {"ok": True},
        }
    )
    # Read tools pass the vendor's own payload through unchanged (same convention as every
    # existing read tool, e.g. threatlocker_computers_get): the id/organization context the
    # caller already has is what "identifies what it read" (AC10), not a synthesized wrapper.
    get_result = await _call(monkeypatch, rec, "threatlocker_ringfence_get", {"ringfencePolicyId": POLICY_ID})
    assert get_result["ringfencePolicyId"] == POLICY_ID
    eligibility_result = await _call(monkeypatch, rec, "threatlocker_ringfence_eligibility", {})
    assert eligibility_result == {"eligible": True}
    # The one mutating ringfencing tool gets the explicit {action, result} wrapper, like the
    # 3 mutating approval tools.
    opt_in_result = await _call(monkeypatch, rec, "threatlocker_ringfence_opt_in", {})
    assert opt_in_result == {"action": "opt_in", "result": {"ok": True}}
