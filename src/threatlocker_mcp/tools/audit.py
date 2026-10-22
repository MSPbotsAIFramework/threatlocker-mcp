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
"""Unified audit (action log): what ran, what was blocked, and why."""

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ThreatLockerClient, ThreatLockerError
from ._common import (
    DEFAULT_PAGE_SIZE,
    READ_ONLY,
    ChildOrganizations,
    ClientFactory,
    PageNumber,
    PageSize,
    compact,
    guid,
    page_result,
    rows,
    run_tool,
)

SOURCE_TABLES = "1 = ActionLog, 2 = DenyActionLog, 3 = BaselineActionLog, 4 = EventLogActionLog"
SourceTableId = Annotated[int | None, Field(description=f"Source table of the row: {SOURCE_TABLES}.", ge=1, le=4)]
_NUMERIC = re.compile(r"^-?\d+$")
# Audit search reads source table 1 (ActionLogParamsDto.sourceTableId defaults to 1) and its rows
# carry no table id, so a lookup without one tries 1, then 2. Without any, the API answers 500.
_DEFAULT_TABLES = (1, 2)


async def get_audit_entry(client: ThreatLockerClient, ident: str, table: int | None) -> Any:
    """ActionLogGetByIdV2 for one eActionLogId, trying the default tables when none is given."""
    if table is not None:
        return await client.get("ActionLog/ActionLogGetByIdV2", {"eActionLogId": ident, "sourceTableId": table})
    for candidate in _DEFAULT_TABLES:
        try:
            entry = await client.get("ActionLog/ActionLogGetByIdV2", {"eActionLogId": ident, "sourceTableId": candidate})
        except ThreatLockerError as e:
            if e.status_code not in (400, 404) and e.status_code < 500:
                raise  # e.g. 401 no permission: the same for every table
            continue
        if entry:
            return {"sourceTableId": candidate, **entry} if isinstance(entry, dict) else entry
    raise ThreatLockerError(
        404,
        f"No audit entry {ident} in source tables 1 (ActionLog) or 2 (DenyActionLog); "
        "pass sourceTableId 3 (BaselineActionLog) or 4 (EventLogActionLog) if it comes from those.",
    )


def _instant(value: str | None, name: str) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"{name} must be an ISO 8601 date or time, e.g. 2026-06-01T00:00:00Z (got {value!r}).") from e
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def search_window(start: str | None, end: str | None, now: datetime | None = None) -> tuple[str, str]:
    """[start, end] as ISO UTC; defaults to the 24 hours before end (or now)."""
    end_at = _instant(end, "endDate") or now or datetime.now(UTC)
    start_at = _instant(start, "startDate") or end_at - timedelta(days=1)
    if start_at >= end_at:
        raise ValueError("startDate must be before endDate.")
    return _iso(start_at), _iso(end_at)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_audit_search(
        searchText: Annotated[str | None, Field(description="Text the file path contains, e.g. a program name.")] = None,
        startDate: Annotated[str | None, Field(description="Window start, ISO 8601 (default 24 h before endDate).")] = None,
        endDate: Annotated[str | None, Field(description="Window end, ISO 8601 (default now).")] = None,
        pageNumber: PageNumber = None,
        pageSize: PageSize = None,
        childOrganizations: ChildOrganizations = None,
        hostname: Annotated[str | None, Field(description="Only this computer (hostname).")] = None,
        actionType: Annotated[str | None, Field(description="Only this action type, e.g. execute, read, write, network.")] = None,
    ) -> str:
        """Search the unified audit: which files ran, were blocked or were permitted, where and when.

        Rows carry eActionLogId for threatlocker_audit_get. The API reports no total while more
        pages exist: total is given only on the last page (has_more false).
        """

        async def action(client: ThreatLockerClient) -> dict:
            number, size = pageNumber or 1, pageSize or DEFAULT_PAGE_SIZE
            start, end = search_window(startDate, endDate)
            body = compact(
                {
                    "startDate": start,
                    "endDate": end,
                    "pageNumber": number,
                    "pageSize": size,
                    "paramsFieldsDto": [],
                    "showChildOrganizations": bool(childOrganizations),
                    "fullPath": (searchText or "").strip() or None,
                    "hostname": (hostname or "").strip() or None,
                    "actionType": (actionType or "").strip() or None,
                }
            )
            page = await client.post("ActionLog/ActionLogGetByParametersV2", body, headers={"usenewsearch": "true"})
            result = page_result(page, number, size)
            # The new search's totalItems is "rows up to this page + 1", not a total: keep it only
            # for has_more, and give the real total once the last page is reached.
            result.pop("total", None)
            if not result["has_more"]:
                result["total"] = (number - 1) * size + result["count"]
            return {"window": {"start": start, "end": end}, **result}

        return await run_tool("threatlocker_audit_search", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_audit_get(
        eActionLogId: Annotated[
            str | None, Field(description="eActionLogId (a string) from a threatlocker_audit_search row.")
        ] = None,
        sourceTableId: SourceTableId = None,
        actionLogId: Annotated[
            str | None, Field(description="Deprecated alias for eActionLogId; the numeric actionLogId is not accepted.")
        ] = None,
    ) -> str:
        """Get one audit entry in full by its eActionLogId (not the numeric actionLogId).

        For a threatlocker_audit_search row, pass only eActionLogId: tables 1 then 2 are tried.
        """

        async def action(client: ThreatLockerClient) -> Any:
            ident = (eActionLogId or actionLogId or "").strip()
            if not ident:
                raise ValueError("Pass eActionLogId, the string id on a threatlocker_audit_search row.")
            if _NUMERIC.match(ident):
                raise ValueError(
                    "That is the numeric actionLogId; this lookup needs the row's eActionLogId string "
                    "(from threatlocker_audit_search)."
                )
            return await get_audit_entry(client, ident, sourceTableId)

        return await run_tool("threatlocker_audit_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_audit_file_history(
        fullPath: Annotated[str, Field(description="Full path of the file.", min_length=1)],
        hostname: Annotated[str | None, Field(description="Computer hostname (this or computerId is required).")] = None,
        computerId: Annotated[str | None, Field(description="Computer id, a GUID (this or hostname is required).")] = None,
        sourceTableId: SourceTableId = None,
        pageNumber: PageNumber = None,
        pageSize: PageSize = None,
    ) -> str:
        """Get the audit history of one file on one computer (needs fullPath plus hostname or computerId)."""

        async def action(client: ThreatLockerClient) -> dict:
            host = (hostname or "").strip()
            if not host and not computerId:
                raise ValueError("Pass hostname or computerId together with fullPath.")
            params = compact(
                {
                    "fullPath": fullPath.strip(),
                    "hostname": host or None,
                    "computerId": guid(computerId, "computerId") if computerId else None,
                    "sourceTableId": sourceTableId,
                    "pageNumber": pageNumber,
                    "pageSize": pageSize,
                }
            )
            history = rows(await client.get("ActionLog/ActionLogGetAllForFileHistoryV2", params))
            return {"history": history, "count": len(history)}

        return await run_tool("threatlocker_audit_file_history", client_factory, action)
