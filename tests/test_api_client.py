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
"""Instance detection, request shapes, paging and retries against a mocked Portal API."""

import json
from datetime import UTC, datetime

import httpx
import pytest

from threatlocker_mcp import api_client
from threatlocker_mcp.api_client import ThreatLockerClient, ThreatLockerCredentials, ThreatLockerError
from threatlocker_mcp.server import _credentials_var, create_mcp_server
from threatlocker_mcp.tools.audit import search_window

ORG = "11111111-2222-3333-4444-555555555555"
COMPUTER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CREDS = ThreatLockerCredentials(api_key="key-123", organization_id=ORG, instance="g")


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


def _client(recorder: Recorder, credentials: ThreatLockerCredentials = CREDS) -> ThreatLockerClient:
    return ThreatLockerClient(credentials, httpx.AsyncClient(transport=httpx.MockTransport(recorder)))


# ---- authentication and instance -------------------------------------------


async def test_raw_key_and_managed_organization_headers():
    rec = Recorder()
    await _client(rec).get("Organization/OrganizationGetForMoveComputers")
    request = rec.requests[0]
    assert str(request.url) == "https://portalapi.g.threatlocker.com/portalapi/Organization/OrganizationGetForMoveComputers"
    assert request.headers["Authorization"] == "key-123"
    assert request.headers["ManagedOrganizationId"] == ORG


async def test_instance_is_detected_and_cached():
    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200 if request.url.host == "portalapi.d.threatlocker.com" else 401, json=0)

    rec = Recorder({"ApprovalRequest/ApprovalRequestGetCount": route, "Organization/OrganizationGetForMoveComputers": route})
    creds = ThreatLockerCredentials(api_key="key-123", organization_id=ORG)
    client = _client(rec, creds)
    await client.get("Organization/OrganizationGetForMoveComputers")
    assert client.instance == "d"
    assert rec.requests[-1].url.host == "portalapi.d.threatlocker.com"
    probes = len(rec.requests) - 1
    assert probes == 7
    second = _client(rec, creds)
    await second.get("Organization/OrganizationGetForMoveComputers")
    assert len(rec.requests) == probes + 2


async def test_expired_instance_entry_is_probed_again(monkeypatch):
    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200 if request.url.host == "portalapi.d.threatlocker.com" else 401, json=0)

    monkeypatch.setattr(api_client, "_INSTANCE_CACHE_TTL_SECONDS", -1.0)
    rec = Recorder({"ApprovalRequest/ApprovalRequestGetCount": route, "Organization/OrganizationGetForMoveComputers": route})
    creds = ThreatLockerCredentials(api_key="key-123", organization_id=ORG)
    await _client(rec, creds).get("Organization/OrganizationGetForMoveComputers")
    assert len(rec.requests) == 8
    second = _client(rec, creds)
    await second.get("Organization/OrganizationGetForMoveComputers")
    assert second.instance == "d"
    assert len(rec.requests) == 16
    assert len(api_client._instance_cache) == 1


async def test_no_instance_accepts_the_key(monkeypatch):
    rec = Recorder(default=lambda r: httpx.Response(401, json={"message": "Unauthorized"}))
    creds = ThreatLockerCredentials(api_key="key-123", organization_id=ORG)
    result = await _call(monkeypatch, rec, "threatlocker_status", {}, creds)
    assert result["error"]["code"] == "unauthorized"
    assert "X-Threatlocker-Instance" in result["error"]["message"]
    assert "key-123" not in json.dumps(result)


async def test_retries_5xx_then_succeeds():
    replies = iter([httpx.Response(503), httpx.Response(200, json=3)])
    rec = Recorder({"ApprovalRequest/ApprovalRequestGetCount": lambda r: next(replies)})
    assert await _client(rec).get("ApprovalRequest/ApprovalRequestGetCount") == 3
    assert len(rec.requests) == 2


async def test_error_message_from_body():
    rec = Recorder(default=lambda r: httpx.Response(417, json="Missing Parameters. Unable to load details."))
    with pytest.raises(ThreatLockerError) as err:
        await _client(rec).get("ActionLog/ActionLogGetAllForFileHistoryV2")
    assert err.value.status_code == 417
    assert "Missing Parameters" in err.value.message


# ---- computers -------------------------------------------------------------


async def test_computers_list_body_and_paging_header(monkeypatch):
    def route(request: httpx.Request) -> httpx.Response:
        headers = {"pagination": json.dumps({"currentPage": 2, "totalPages": 5, "totalItems": 101})}
        return httpx.Response(200, json=[{"computerId": COMPUTER}], headers=headers)

    rec = Recorder({"POST Computer/ComputerGetByAllParameters": route})
    args = {"searchText": "laptop", "computerGroup": COMPUTER, "pageNumber": 2, "pageSize": 10}
    result = await _call(monkeypatch, rec, "threatlocker_computers_list", args)
    assert body(rec.requests[0]) == {
        "searchText": "laptop",
        "computerGroup": COMPUTER,
        "pageNumber": 2,
        "pageSize": 10,
        "childOrganizations": False,
        "showLastCheckIn": True,
    }
    assert (result["count"], result["total"], result["has_more"], result["page"]) == (1, 101, True, 2)


async def test_computer_ids_must_be_guids(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "threatlocker_computers_get", {"computerId": "12345"})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_checkins_body(monkeypatch):
    rec = Recorder({"POST ComputerCheckin/ComputerCheckinGetByParameters": []})
    await _call(monkeypatch, rec, "threatlocker_computers_get_checkins", {"computerId": COMPUTER})
    assert body(rec.requests[0]) == {
        "computerId": COMPUTER,
        "pageNumber": 1,
        "pageSize": 25,
        "hideHeartbeat": True,
        "showTotalCount": True,
    }


async def test_groups_os_type_is_numeric(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "threatlocker_computer_groups_list", {"osType": "1", "includeGlobal": True})
    params = rec.requests[0].url.params
    assert (params["OSType"], params["IncludeGlobal"]) == ("1", "true")
    result = await _call(monkeypatch, Recorder(), "threatlocker_computer_groups_list", {"osType": "Windows"})
    assert result["error"]["code"] == "invalid_argument"


# ---- approvals -------------------------------------------------------------


@pytest.mark.parametrize("status,expected", [(None, 1), ("Approved", 4), ("self approved", 16), ("Denied", 10)])
async def test_approvals_status_ids(monkeypatch, status, expected):
    rec = Recorder({"POST ApprovalRequest/ApprovalRequestGetByParameters": []})
    args = {"status": status} if status else {}
    await _call(monkeypatch, rec, "threatlocker_approvals_list", args)
    sent = body(rec.requests[0])
    assert sent["statusId"] == expected
    assert (sent["orderBy"], sent["isAscending"]) == ("datetime", False)


async def test_approvals_unknown_status(monkeypatch):
    result = await _call(monkeypatch, Recorder(), "threatlocker_approvals_list", {"status": "maybe"})
    assert result["error"]["code"] == "invalid_argument"


async def test_pending_count(monkeypatch):
    rec = Recorder({"ApprovalRequest/ApprovalRequestGetCount": 7})
    assert await _call(monkeypatch, rec, "threatlocker_approvals_pending_count", {}) == {"pending_count": 7}


# ---- audit -----------------------------------------------------------------


def test_search_window_defaults_to_24_hours():
    now = datetime(2026, 6, 2, 12, 0, tzinfo=UTC)
    assert search_window(None, None, now) == ("2026-06-01T12:00:00Z", "2026-06-02T12:00:00Z")
    assert search_window("2026-05-01", "2026-05-03T00:00:00Z") == ("2026-05-01T00:00:00Z", "2026-05-03T00:00:00Z")
    with pytest.raises(ValueError):
        search_window("2026-05-03", "2026-05-01")


async def test_audit_search_body(monkeypatch):
    rec = Recorder({"POST ActionLog/ActionLogGetByParametersV2": []})
    args = {"searchText": "chrome.exe", "startDate": "2026-06-01", "endDate": "2026-06-02", "hostname": "PC-01"}
    result = await _call(monkeypatch, rec, "threatlocker_audit_search", args)
    request = rec.requests[0]
    assert request.headers["usenewsearch"] == "true"
    assert body(request) == {
        "startDate": "2026-06-01T00:00:00Z",
        "endDate": "2026-06-02T00:00:00Z",
        "pageNumber": 1,
        "pageSize": 25,
        "paramsFieldsDto": [],
        "showChildOrganizations": False,
        "fullPath": "chrome.exe",
        "hostname": "PC-01",
    }
    assert result["window"] == {"start": "2026-06-01T00:00:00Z", "end": "2026-06-02T00:00:00Z"}


@pytest.mark.parametrize("args", [{}, {"eActionLogId": "12345"}, {"actionLogId": "678"}])
async def test_audit_get_needs_the_string_id(monkeypatch, args):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "threatlocker_audit_get", args)
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


async def test_audit_get_accepts_alias(monkeypatch):
    rec = Recorder({"ActionLog/ActionLogGetByIdV2": {"fullPath": "C:\\x.exe"}})
    await _call(monkeypatch, rec, "threatlocker_audit_get", {"actionLogId": "a1b2c3", "sourceTableId": 2})
    params = rec.requests[0].url.params
    assert (params["eActionLogId"], params["sourceTableId"]) == ("a1b2c3", "2")


async def test_file_history_needs_a_computer(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "threatlocker_audit_file_history", {"fullPath": "C:\\x.exe"})
    assert result["error"]["code"] == "invalid_argument"
    rec = Recorder({"ActionLog/ActionLogGetAllForFileHistoryV2": {"logs": [{"id": 1}]}})
    result = await _call(monkeypatch, rec, "threatlocker_audit_file_history", {"fullPath": "C:\\x.exe", "computerId": COMPUTER})
    assert result == {"history": [{"id": 1}], "count": 1}
    assert rec.requests[0].url.params["computerId"] == COMPUTER


# ---- organizations ---------------------------------------------------------


async def test_children_body(monkeypatch):
    rec = Recorder({"POST Organization/OrganizationGetChildOrganizationsByParameters": {"items": [{"name": "A"}], "totalItems": 1}})
    result = await _call(monkeypatch, rec, "threatlocker_organizations_list_children", {"searchText": "example"})
    assert body(rec.requests[0])["searchText"] == "example"
    assert (result["count"], result["total"], result["has_more"]) == (1, 1, False)


async def test_move_targets(monkeypatch):
    rec = Recorder({"Organization/OrganizationGetForMoveComputers": {"organizations": [{"name": "B"}]}})
    result = await _call(monkeypatch, rec, "threatlocker_organizations_for_move_computers", {})
    assert result == {"organizations": [{"name": "B"}], "count": 1}



# ---- PRD-20958: audit_get without sourceTableId -------------------------------------------------


async def test_audit_get_without_table_uses_table_1(monkeypatch):
    rec = Recorder({"ActionLog/ActionLogGetByIdV2": {"fullPath": "C:\\x.exe"}})
    result = await _call(monkeypatch, rec, "threatlocker_audit_get", {"eActionLogId": "49e68408-f10f-40af-9e60-f140980b39f4"})
    assert [r.url.params["sourceTableId"] for r in rec.requests] == ["1"]
    assert result == {"sourceTableId": 1, "fullPath": "C:\\x.exe"}


async def test_audit_get_falls_back_to_table_2(monkeypatch):
    def reply(request):
        if request.url.params["sourceTableId"] == "1":
            return httpx.Response(500, json={"message": "A problem occurred with the request"})
        return httpx.Response(200, json={"fullPath": "C:\\blocked.exe"})

    rec = Recorder({"ActionLog/ActionLogGetByIdV2": reply})
    result = await _call(monkeypatch, rec, "threatlocker_audit_get", {"eActionLogId": "b1aa6996"})
    assert result["sourceTableId"] == 2 and result["fullPath"] == "C:\\blocked.exe"
    assert rec.requests[-1].url.params["sourceTableId"] == "2"


async def test_audit_get_not_in_default_tables_is_not_found(monkeypatch):
    rec = Recorder({"ActionLog/ActionLogGetByIdV2": lambda r: httpx.Response(200, json=None)})
    result = await _call(monkeypatch, rec, "threatlocker_audit_get", {"eActionLogId": "b1aa6996"})
    assert result["error"]["code"] == "not_found" and "sourceTableId" in result["error"]["message"]


async def test_audit_get_permission_error_is_not_retried_on_another_table(monkeypatch):
    rec = Recorder({"ActionLog/ActionLogGetByIdV2": lambda r: httpx.Response(401, json={"message": "No permission"})})
    result = await _call(monkeypatch, rec, "threatlocker_audit_get", {"eActionLogId": "b1aa6996"})
    assert result["error"]["code"] == "unauthorized" and len(rec.requests) == 1


async def test_audit_get_explicit_table_is_used_as_given(monkeypatch):
    rec = Recorder({"ActionLog/ActionLogGetByIdV2": {"fullPath": "C:\\x.exe"}})
    await _call(monkeypatch, rec, "threatlocker_audit_get", {"eActionLogId": "b1aa6996", "sourceTableId": 3})
    assert [r.url.params["sourceTableId"] for r in rec.requests] == ["3"]


# ---- PRD-20959: audit_search total ---------------------------------------------------------------


@pytest.mark.parametrize(
    "number,rows,total_items,expected",
    [(1, 3, 4, None), (2, 3, 7, None), (10, 3, 31, None), (4, 2, 11, 11)],
)
async def test_audit_search_reports_total_only_on_the_last_page(monkeypatch, number, rows, total_items, expected):
    reply = {"data": [{"eActionLogId": f"e{i}"} for i in range(rows)], "totalItems": total_items}
    rec = Recorder({"POST ActionLog/ActionLogGetByParametersV2": lambda r: httpx.Response(
        200, json=reply["data"], headers={"pagination": json.dumps({"totalItems": total_items})})})
    result = await _call(monkeypatch, rec, "threatlocker_audit_search", {"pageNumber": number, "pageSize": 3})
    assert result.get("total") == expected
    assert result["has_more"] is (expected is None)
