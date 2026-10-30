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
"""Tool discovery (kept for compatibility) and the connection check."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import compact as to_json
from ..api_client import ThreatLockerClient
from ._common import LOCAL, READ_ONLY, ClientFactory, run_tool

DOMAINS: dict[str, tuple[str, list[str]]] = {
    "computers": (
        "Protected computers and their check-ins.",
        ["threatlocker_computers_list", "threatlocker_computers_get", "threatlocker_computers_get_checkins"],
    ),
    "computer_groups": (
        "Computer groups.",
        ["threatlocker_computer_groups_list", "threatlocker_computer_groups_dropdown"],
    ),
    "approval_requests": (
        "Requests to allow blocked software: read them, and decide them (approve/reject/ignore).",
        [
            "threatlocker_approvals_list",
            "threatlocker_approvals_get",
            "threatlocker_approvals_pending_count",
            "threatlocker_approvals_get_permit_application",
            "threatlocker_approvals_approve",
            "threatlocker_approvals_reject",
            "threatlocker_approvals_ignore",
        ],
    ),
    "audit_log": (
        "Unified audit of what ran or was blocked.",
        ["threatlocker_audit_search", "threatlocker_audit_get", "threatlocker_audit_file_history"],
    ),
    "organizations": (
        "Child organizations, install key, move targets.",
        [
            "threatlocker_organizations_list_children",
            "threatlocker_organizations_get_auth_key",
            "threatlocker_organizations_for_move_computers",
        ],
    ),
    "ringfencing": (
        "Read a Ringfencing policy, check eligibility, and opt the organization in. The public API "
        "has no endpoint to edit a policy's rule content.",
        [
            "threatlocker_ringfence_get",
            "threatlocker_ringfence_eligibility",
            "threatlocker_ringfence_opt_in",
        ],
    ),
}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=LOCAL)
    async def threatlocker_navigate(
        domain: Annotated[
            Literal["computers", "computer_groups", "approval_requests", "audit_log", "organizations", "ringfencing"],
            Field(description="Area to describe."),
        ],
    ) -> str:
        """Describe the tools of one ThreatLocker area. All tools are already callable; this changes nothing."""
        summary, tools = DOMAINS[domain]
        return to_json({"domain": domain, "summary": summary, "tools": tools})

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_status() -> str:
        """Check the ThreatLocker connection (key, organization, portal instance) and list the tool areas."""

        async def action(client: ThreatLockerClient) -> dict:
            pending = await client.get("ApprovalRequest/ApprovalRequestGetCount")
            return {
                "connected": True,
                "instance": client.instance,
                "pending_approval_requests": pending if isinstance(pending, int) else None,
                "domains": {name: summary for name, (summary, _tools) in DOMAINS.items()},
            }

        return await run_tool("threatlocker_status", client_factory, action)
