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
"""Approval requests: users asking for blocked software to be allowed (read-only here)."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ThreatLockerClient
from ._common import (
    READ_ONLY,
    ChildOrganizations,
    ClientFactory,
    Offset,
    PageNumber,
    PageSize,
    SearchText,
    guid,
    locate,
    page_result,
    run_tool,
)

# Portal status ids for approval requests.
STATUS_IDS = {
    "pending": 1,
    "approved": 4,
    "notlearned": 6,
    "rejected": 10,
    "denied": 10,
    "addedtoapplication": 12,
    "escalated": 13,
    "selfapproved": 16,
}
ApprovalRequestId = Annotated[str, Field(description="Approval request id (GUID) from threatlocker_approvals_list.", min_length=1)]


def status_id(status: str | None) -> int:
    if not status or status.strip().lower() == "all":
        return STATUS_IDS["pending"]
    key = "".join(ch for ch in status.lower() if ch.isalpha())
    if key not in STATUS_IDS:
        raise ValueError(
            f"Unknown status {status!r}; use Pending, Approved, Rejected (Denied), Not Learned, "
            "Added To Application, Escalated or Self Approved."
        )
    return STATUS_IDS[key]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_approvals_list(
        status: Annotated[
            str | None,
            Field(description="Pending (default), Approved, Rejected / Denied, Not Learned, Added To Application, Escalated, Self Approved."),
        ] = None,
        pageNumber: PageNumber = None,
        pageSize: PageSize = None,
        searchText: SearchText = None,
        childOrganizations: ChildOrganizations = None,
        offset: Offset = None,
    ) -> str:
        """List approval requests (blocked software users asked to run), newest first, by status."""

        async def action(client: ThreatLockerClient) -> dict:
            number, size, start = locate(offset, pageNumber, pageSize)
            body = {
                "statusId": status_id(status),
                "searchText": (searchText or "").strip(),
                "pageNumber": number,
                "pageSize": size,
                "orderBy": "datetime",
                "isAscending": False,
                "showChildOrganizations": bool(childOrganizations),
            }
            result = page_result(await client.post("ApprovalRequest/ApprovalRequestGetByParameters", body), number, size, start)
            if status and status.strip().lower() == "all":
                result["note"] = "The API filters by one status; showing Pending."
            return result

        return await run_tool("threatlocker_approvals_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_approvals_get(approvalRequestId: ApprovalRequestId) -> str:
        """Get one approval request: requester, computer, file, hash, certificate, justification and status."""

        async def action(client: ThreatLockerClient) -> Any:
            return await client.get(
                "ApprovalRequest/ApprovalRequestGetById", {"approvalRequestId": guid(approvalRequestId, "approvalRequestId")}
            )

        return await run_tool("threatlocker_approvals_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_approvals_pending_count() -> str:
        """Count pending approval requests waiting for a technician."""

        async def action(client: ThreatLockerClient) -> dict:
            payload = await client.get("ApprovalRequest/ApprovalRequestGetCount")
            count = payload if isinstance(payload, int) else payload.get("count") if isinstance(payload, dict) else payload
            return {"pending_count": count}

        return await run_tool("threatlocker_approvals_pending_count", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_approvals_get_permit_application(approvalRequestId: ApprovalRequestId) -> str:
        """Get what approving a request would permit: the matching application and its rules."""

        async def action(client: ThreatLockerClient) -> Any:
            return await client.get(
                "ApprovalRequest/ApprovalRequestGetPermitApplicationById",
                {"approvalRequestId": guid(approvalRequestId, "approvalRequestId")},
            )

        return await run_tool("threatlocker_approvals_get_permit_application", client_factory, action)
