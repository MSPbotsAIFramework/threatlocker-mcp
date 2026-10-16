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
"""Organizations: child (customer) organizations, install key, move targets."""

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..api_client import ThreatLockerClient
from ._common import (
    DEFAULT_PAGE_SIZE,
    READ_ONLY,
    ClientFactory,
    PageNumber,
    PageSize,
    SearchText,
    page_result,
    rows,
    run_tool,
)


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_organizations_list_children(
        searchText: SearchText = None,
        pageNumber: PageNumber = None,
        pageSize: PageSize = None,
    ) -> str:
        """List child (customer) organizations under the managed organization, with their ids."""

        async def action(client: ThreatLockerClient) -> dict:
            number, size = pageNumber or 1, pageSize or DEFAULT_PAGE_SIZE
            body = {
                "searchText": (searchText or "").strip(),
                "pageNumber": number,
                "pageSize": size,
                "orderBy": "name",
                "isAscending": True,
                "includeAllChildren": True,
            }
            page = await client.post("Organization/OrganizationGetChildOrganizationsByParameters", body)
            return page_result(page, number, size)

        return await run_tool("threatlocker_organizations_list_children", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_organizations_get_auth_key() -> str:
        """Get the organization's agent install key. A secret: only when the user explicitly asks.

        Anyone with it can enroll computers into the organization; do not post it in tickets or chats.
        """

        async def action(client: ThreatLockerClient) -> Any:
            return await client.get("Organization/OrganizationGetAuthKeyById")

        return await run_tool("threatlocker_organizations_get_auth_key", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_organizations_for_move_computers() -> str:
        """List the organizations computers may be moved to from the managed organization."""

        async def action(client: ThreatLockerClient) -> dict:
            organizations = rows(await client.get("Organization/OrganizationGetForMoveComputers"))
            return {"organizations": organizations, "count": len(organizations)}

        return await run_tool("threatlocker_organizations_for_move_computers", client_factory, action)
