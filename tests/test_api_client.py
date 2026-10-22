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


def _audit_page(rows, total_items):
    """One audit-search reply: `rows` rows, and the API's pagination header (its totalItems)."""
    data = [{"eActionLogId": f"e{i}"} for i in range(rows)]
    return lambda r: httpx.Response(200, json=data, headers={"pagination": json.dumps({"totalItems": total_items})})


# QA retests of PRD-20959 (32-row window), one row per call. totalItems is what the API sent:
# "rows up to this page + 1" while more exist, the row count on the last page, and a value that
# grows with the page number on empty pages past the end.
@pytest.mark.parametrize(
    "size,number,rows,total_items,expected_total",
    [
        (5, 1, 5, 6, None),  # normal walk, pages 1-6: no total
        (5, 6, 5, 31, None),
        (5, 7, 2, 32, 32),  # real last page: total 32
        (10, 4, 2, 32, 32),  # real last page
        (10, 5, 0, 40, None),  # past the end: API says 40
        (5, 8, 0, 35, None),  # past the end: API says 35
        (50, 2, 0, 50, None),  # past the end: API says 50
        (50, 3, 0, 100, None),  # past the end: API says 100
        (50, 1, 32, 32, 32),  # everything on page 1
        (50, 1, 0, 0, 0),  # empty window: the total really is 0
        (3, 1, 3, 4, None),  # first retest, 24 h window: 3 / 4
        (3, 10, 3, 31, None),  # ... page 10: 3 / 31
    ],
)
async def test_audit_search_total_matches_qa_retests(monkeypatch, size, number, rows, total_items, expected_total):
    rec = Recorder({"POST ActionLog/ActionLogGetByParametersV2": _audit_page(rows, total_items)})
    result = await _call(monkeypatch, rec, "threatlocker_audit_search", {"pageNumber": number, "pageSize": size})
    assert result.get("total") == expected_total
    assert result["count"] == rows
    last = expected_total is not None or rows == 0
    assert result["has_more"] is (not last)
    if rows == 0 and number > 1:
        assert "past the last page" in result["note"]


async def test_audit_search_total_never_changes_with_the_page_number(monkeypatch):
    # Acceptance: the same window never reports two different totals, whatever page is asked.
    seen = set()
    for size, number, rows, total_items in [(5, 7, 2, 32), (10, 4, 2, 32), (10, 5, 0, 40), (5, 8, 0, 35),
                                            (50, 2, 0, 50), (50, 3, 0, 100), (50, 1, 32, 32)]:
        rec = Recorder({"POST ActionLog/ActionLogGetByParametersV2": _audit_page(rows, total_items)})
        result = await _call(monkeypatch, rec, "threatlocker_audit_search", {"pageNumber": number, "pageSize": size})
        if "total" in result:
            seen.add(result["total"])
    assert seen == {32}



# ---- Page-number paging that survives truncation (offset / next_offset) -----------------------------
# Self-test checklist: a cut page continues right after the last record returned (from page 1 and
# from a later page); offset aligned / not aligned to a page; offset past the end; offset wins over
# pageNumber; pageNumber-only calls send the same request as before; no retry hint for a page size.

TOTAL = 137
ROWS = [{"id": f"r{i:03d}", "name": f"Row {i}", **{f"f{k}": f"value {k}" for k in range(40)}} for i in range(TOTAL)]
SMALL = [{"id": f"r{i:03d}"} for i in range(TOTAL)]

PAGED_TOOLS = [
    ("threatlocker_computers_list", "POST Computer/ComputerGetByAllParameters", {}),
    ("threatlocker_computers_get_checkins", "POST ComputerCheckin/ComputerCheckinGetByParameters", {"computerId": ORG}),
    ("threatlocker_approvals_list", "POST ApprovalRequest/ApprovalRequestGetByParameters", {}),
    ("threatlocker_organizations_list_children", "POST Organization/OrganizationGetChildOrganizationsByParameters", {}),
    ("threatlocker_audit_search", "POST ActionLog/ActionLogGetByParametersV2", {}),
]


def _paged_api(rows, audit=False):
    """Pages by pageNumber / pageSize like ThreatLocker; audit search reports "rows so far + 1"."""

    def reply(request):
        sent = body(request)
        number, size = sent["pageNumber"], sent["pageSize"]
        chunk = rows[(number - 1) * size : number * size]
        more = number * size < len(rows)
        total = min(len(rows), number * size + 1) if audit and more else len(rows)
        return httpx.Response(200, json=chunk, headers={"pagination": json.dumps({"totalItems": total})})

    return reply


def _api(route, rows):
    return Recorder({route: _paged_api(rows, audit="ActionLogGetByParametersV2" in route)})


async def _walk(monkeypatch, rec, tool, args):
    ids, calls, cut = [], 0, 0
    while True:
        result = await _call(monkeypatch, rec, tool, args)
        calls += 1
        assert "retry_page_size" not in result, result.get("note")
        cut += bool(result.get("truncated"))
        ids += [r["id"] for r in result["items"]]
        if result.get("next_offset") is None:
            return ids, calls, cut
        args = {k: v for k, v in args.items() if k != "pageNumber"} | {"offset": result["next_offset"]}
        assert calls < 200


@pytest.mark.parametrize("tool,route,extra", PAGED_TOOLS)
async def test_cut_pages_continue_without_gaps_from_page_1(monkeypatch, tool, route, extra):
    ids, _, cut = await _walk(monkeypatch, _api(route, ROWS), tool, extra | {"pageSize": 50})
    assert cut > 0  # pages really were cut
    assert ids == [r["id"] for r in ROWS]  # no gaps, no duplicates


@pytest.mark.parametrize("tool,route,extra", PAGED_TOOLS)
async def test_cut_pages_continue_without_gaps_from_a_later_page(monkeypatch, tool, route, extra):
    ids, _, cut = await _walk(monkeypatch, _api(route, ROWS), tool, extra | {"pageNumber": 3, "pageSize": 40})
    assert cut > 0
    assert ids == [r["id"] for r in ROWS[80:]]


@pytest.mark.parametrize("tool,route,extra", PAGED_TOOLS)
@pytest.mark.parametrize("offset,size,page,first", [(30, 25, 2, "r030"), (50, 25, 3, "r050"), (0, 25, 1, "r000")])
async def test_offset_reads_the_page_that_holds_it(monkeypatch, tool, route, extra, offset, size, page, first):
    rec = _api(route, SMALL)
    result = await _call(monkeypatch, rec, tool, extra | {"offset": offset, "pageSize": size})
    assert (body(rec.requests[0])["pageNumber"], body(rec.requests[0])["pageSize"]) == (page, size)
    assert result["items"][0]["id"] == first and result["offset"] == offset
    assert result["next_offset"] == page * size  # rest of the page returned, next page starts after it


@pytest.mark.parametrize("tool,route,extra", PAGED_TOOLS)
async def test_offset_past_the_end_is_empty(monkeypatch, tool, route, extra):
    result = await _call(monkeypatch, _api(route, SMALL), tool, extra | {"offset": 500, "pageSize": 25})
    assert (result["count"], result["has_more"], result.get("next_offset")) == (0, False, None)


@pytest.mark.parametrize("tool,route,extra", PAGED_TOOLS)
async def test_offset_wins_over_page_number(monkeypatch, tool, route, extra):
    rec = _api(route, SMALL)
    result = await _call(monkeypatch, rec, tool, extra | {"offset": 10, "pageNumber": 4, "pageSize": 10})
    assert body(rec.requests[0])["pageNumber"] == 2 and result["items"][0]["id"] == "r010"


@pytest.mark.parametrize("tool,route,extra", PAGED_TOOLS)
async def test_page_number_only_sends_the_same_request_as_before(monkeypatch, tool, route, extra):
    rec = _api(route, SMALL)
    result = await _call(monkeypatch, rec, tool, extra | {"pageNumber": 2, "pageSize": 25})
    assert (body(rec.requests[0])["pageNumber"], body(rec.requests[0])["pageSize"]) == (2, 25)
    assert [r["id"] for r in result["items"]] == [f"r{i:03d}" for i in range(25, 50)]
    assert (result["page"], result["offset"], result["next_offset"], result["has_more"]) == (2, 25, 50, True)


async def test_audit_search_total_from_an_offset_inside_the_last_page(monkeypatch):
    rows = SMALL[:32]
    rec = Recorder({"POST ActionLog/ActionLogGetByParametersV2": _paged_api(rows, audit=True)})
    result = await _call(monkeypatch, rec, "threatlocker_audit_search", {"offset": 30, "pageSize": 25})
    assert (result["count"], result["total"], result["has_more"]) == (2, 32, False)
    past = await _call(monkeypatch, rec, "threatlocker_audit_search", {"offset": 40, "pageSize": 25})
    assert past["count"] == 0 and past["total"] == 32  # page 2 still has rows, so the total is known


async def test_approvals_all_status_note_survives_paging(monkeypatch):
    rec = _api("POST ApprovalRequest/ApprovalRequestGetByParameters", SMALL)
    result = await _call(monkeypatch, rec, "threatlocker_approvals_list", {"status": "all", "offset": 5})
    assert result["note"].startswith("The API filters by one status")


def _history_api(rows, seen):
    def reply(request):
        params = dict(request.url.params)
        seen.append(params)
        if "pageNumber" not in params:
            return httpx.Response(200, json=rows)
        number, size = int(params["pageNumber"]), int(params["pageSize"])
        return httpx.Response(200, json=rows[(number - 1) * size : number * size])

    return reply


async def test_file_history_without_paging_is_unchanged_and_a_cut_result_continues(monkeypatch):
    seen = []
    rec = Recorder({"ActionLog/ActionLogGetAllForFileHistoryV2": _history_api(ROWS, seen)})
    args = {"fullPath": "C:/x.exe", "hostname": "PC-01"}
    first = await _call(monkeypatch, rec, "threatlocker_audit_file_history", args)
    assert "pageNumber" not in seen[0] and first["truncated"] is True and "retry_page_size" not in first
    ids, offset, calls = [h["id"] for h in first["history"]], first["next_offset"], 1
    while offset is not None:
        result = await _call(monkeypatch, rec, "threatlocker_audit_file_history", args | {"offset": offset})
        ids += [h["id"] for h in result["history"]]
        offset, calls = result.get("next_offset"), calls + 1
        assert calls < 200
    assert ids == [r["id"] for r in ROWS]


async def test_file_history_offset_reads_the_page_that_holds_it(monkeypatch):
    seen = []
    rec = Recorder({"ActionLog/ActionLogGetAllForFileHistoryV2": _history_api(SMALL, seen)})
    result = await _call(monkeypatch, rec, "threatlocker_audit_file_history", {"fullPath": "C:/x.exe", "hostname": "PC-01", "offset": 30})
    assert (seen[0]["pageNumber"], seen[0]["pageSize"]) == ("2", "25")
    assert result["history"][0]["id"] == "r030" and result["next_offset"] == 50
