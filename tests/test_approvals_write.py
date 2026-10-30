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
"""Approve/reject/ignore an approval request: the first mutating tools (PRD-21247).

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
REQUEST_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PENDING_DTO = {"approvalRequestId": REQUEST_ID, "statusId": 1, "fullPath": "C:\\blocked.exe"}


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

    def calls(self, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == f"/portalapi/{path}"]


def body(request: httpx.Request):
    return json.loads(request.content) if request.content else None


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict, credentials: ThreatLockerCredentials = CREDS):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(credentials)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


# ---- approve -----------------------------------------------------------------


async def test_approve_pending_request_returns_success(monkeypatch):
    rec = Recorder({"POST ApprovalRequest/ApprovalRequestAuthorizeForPermitById": {}})
    result = await _call(monkeypatch, rec, "threatlocker_approvals_approve", {"approvalRequestId": REQUEST_ID})
    assert result == {"approvalRequestId": REQUEST_ID, "action": "approve", "result": {}}
    assert body(rec.requests[0]) == {"approvalRequestId": REQUEST_ID, "message": ""}


async def test_approve_with_message(monkeypatch):
    rec = Recorder({"POST ApprovalRequest/ApprovalRequestAuthorizeForPermitById": {}})
    await _call(monkeypatch, rec, "threatlocker_approvals_approve", {"approvalRequestId": REQUEST_ID, "message": "ok, verified"})
    assert body(rec.requests[0]) == {"approvalRequestId": REQUEST_ID, "message": "ok, verified"}


async def test_approve_unknown_request_returns_error_envelope(monkeypatch):
    rec = Recorder(default=lambda r: httpx.Response(404, json={"message": "Approval request not found"}))
    result = await _call(monkeypatch, rec, "threatlocker_approvals_approve", {"approvalRequestId": REQUEST_ID})
    assert result["error"]["code"] == "not_found"


# ---- reject --------------------------------------------------------------------


async def test_reject_pending_request_returns_success(monkeypatch):
    rec = Recorder(
        {
            "GET ApprovalRequest/ApprovalRequestGetById": PENDING_DTO,
            "POST ApprovalRequest/ApprovalRequestUpdateForReject": {},
        }
    )
    result = await _call(monkeypatch, rec, "threatlocker_approvals_reject", {"approvalRequestId": REQUEST_ID, "reason": "policy violation"})
    assert result == {"approvalRequestId": REQUEST_ID, "action": "reject", "result": {}}
    get_calls = rec.calls("ApprovalRequest/ApprovalRequestGetById")
    assert get_calls[0].url.params["approvalRequestId"] == REQUEST_ID
    post = rec.calls("ApprovalRequest/ApprovalRequestUpdateForReject")[0]
    assert body(post) == {"approvalRequestDtos": [PENDING_DTO], "responseReason": "policy violation", "notifyOnResponse": False}


async def test_reject_unknown_request_never_calls_update_for_reject(monkeypatch):
    rec = Recorder({"GET ApprovalRequest/ApprovalRequestGetById": lambda r: httpx.Response(404, json={"message": "Not found"})})
    result = await _call(monkeypatch, rec, "threatlocker_approvals_reject", {"approvalRequestId": REQUEST_ID, "reason": "x"})
    assert result["error"]["code"] == "not_found"
    assert rec.calls("ApprovalRequest/ApprovalRequestUpdateForReject") == []


# ---- ignore --------------------------------------------------------------------


async def test_ignore_pending_request_returns_success(monkeypatch):
    rec = Recorder(
        {
            "GET ApprovalRequest/ApprovalRequestGetById": PENDING_DTO,
            "POST ApprovalRequest/ApprovalRequestUpdateForIgnore": {},
        }
    )
    result = await _call(monkeypatch, rec, "threatlocker_approvals_ignore", {"approvalRequestId": REQUEST_ID, "reason": "duplicate"})
    assert result == {"approvalRequestId": REQUEST_ID, "action": "ignore", "result": {}}
    post = rec.calls("ApprovalRequest/ApprovalRequestUpdateForIgnore")[0]
    assert body(post) == {"approvalRequestDtos": [PENDING_DTO], "ignoreReason": "duplicate", "notifyOnIgnore": False}


async def test_ignore_unknown_request_never_calls_update_for_ignore(monkeypatch):
    rec = Recorder({"GET ApprovalRequest/ApprovalRequestGetById": lambda r: httpx.Response(404, json={"message": "Not found"})})
    result = await _call(monkeypatch, rec, "threatlocker_approvals_ignore", {"approvalRequestId": REQUEST_ID, "reason": "x"})
    assert result["error"]["code"] == "not_found"
    assert rec.calls("ApprovalRequest/ApprovalRequestUpdateForIgnore") == []


# ---- shared across the 3 mutating approval tools --------------------------------


@pytest.mark.parametrize(
    "tool,args",
    [
        ("threatlocker_approvals_approve", {"approvalRequestId": "not-a-guid"}),
        ("threatlocker_approvals_reject", {"approvalRequestId": "not-a-guid", "reason": "x"}),
        ("threatlocker_approvals_ignore", {"approvalRequestId": "not-a-guid", "reason": "x"}),
    ],
)
async def test_malformed_approval_request_id_never_calls_api(monkeypatch, tool, args):
    rec = Recorder()
    result = await _call(monkeypatch, rec, tool, args)
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


@pytest.mark.parametrize(
    "tool,args",
    [
        ("threatlocker_approvals_approve", {"approvalRequestId": REQUEST_ID}),
        ("threatlocker_approvals_reject", {"approvalRequestId": REQUEST_ID, "reason": "x"}),
        ("threatlocker_approvals_ignore", {"approvalRequestId": REQUEST_ID, "reason": "x"}),
    ],
)
async def test_new_tools_without_credentials_return_not_configured(monkeypatch, tool, args):
    content, _ = await create_mcp_server().call_tool(tool, args)
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"


@pytest.mark.parametrize(
    "tool,args",
    [
        ("threatlocker_approvals_approve", {"approvalRequestId": REQUEST_ID}),
        ("threatlocker_approvals_reject", {"approvalRequestId": REQUEST_ID, "reason": "x"}),
        ("threatlocker_approvals_ignore", {"approvalRequestId": REQUEST_ID, "reason": "x"}),
    ],
)
async def test_two_organizations_never_cross_managed_organization_id(monkeypatch, tool, args):
    rec = Recorder(
        {
            "GET ApprovalRequest/ApprovalRequestGetById": PENDING_DTO,
            "POST ApprovalRequest/ApprovalRequestAuthorizeForPermitById": {},
            "POST ApprovalRequest/ApprovalRequestUpdateForReject": {},
            "POST ApprovalRequest/ApprovalRequestUpdateForIgnore": {},
        }
    )
    creds_a = ThreatLockerCredentials(api_key="key-123", organization_id=ORG_A, instance="g")
    creds_b = ThreatLockerCredentials(api_key="key-456", organization_id=ORG_B, instance="g")
    await _call(monkeypatch, rec, tool, args, creds_a)
    await _call(monkeypatch, rec, tool, args, creds_b)
    org_ids = [r.headers.get("ManagedOrganizationId") for r in rec.requests]
    assert org_ids[: len(org_ids) // 2] == [ORG_A] * (len(org_ids) // 2)
    assert org_ids[len(org_ids) // 2 :] == [ORG_B] * (len(org_ids) // 2)


async def test_success_results_name_id_and_action(monkeypatch):
    rec = Recorder(
        {
            "GET ApprovalRequest/ApprovalRequestGetById": PENDING_DTO,
            "POST ApprovalRequest/ApprovalRequestAuthorizeForPermitById": {"ok": True},
            "POST ApprovalRequest/ApprovalRequestUpdateForReject": {"ok": True},
            "POST ApprovalRequest/ApprovalRequestUpdateForIgnore": {"ok": True},
        }
    )
    approve = await _call(monkeypatch, rec, "threatlocker_approvals_approve", {"approvalRequestId": REQUEST_ID})
    reject = await _call(monkeypatch, rec, "threatlocker_approvals_reject", {"approvalRequestId": REQUEST_ID, "reason": "x"})
    ignore = await _call(monkeypatch, rec, "threatlocker_approvals_ignore", {"approvalRequestId": REQUEST_ID, "reason": "x"})
    for result, action in ((approve, "approve"), (reject, "reject"), (ignore, "ignore")):
        assert result["approvalRequestId"] == REQUEST_ID
        assert result["action"] == action
        assert result["result"] == {"ok": True}
