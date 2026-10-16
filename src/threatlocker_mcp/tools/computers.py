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
"""Computers (protected endpoints), their check-ins, and computer groups."""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ThreatLockerClient
from ._common import (
    DEFAULT_PAGE_SIZE,
    READ_ONLY,
    ChildOrganizations,
    ClientFactory,
    PageNumber,
    PageSize,
    SearchText,
    compact,
    guid,
    page_result,
    rows,
    run_tool,
)

ComputerId = Annotated[str, Field(description="Computer id (GUID) from threatlocker_computers_list.", min_length=1)]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_computers_list(
        searchText: SearchText = None,
        computerGroup: Annotated[str | None, Field(description="Only this computer group (group id, a GUID).")] = None,
        pageNumber: PageNumber = None,
        pageSize: PageSize = None,
        childOrganizations: ChildOrganizations = None,
    ) -> str:
        """List protected computers: name, group, organization, mode, agent version and last check-in."""

        async def action(client: ThreatLockerClient) -> dict:
            number, size = pageNumber or 1, pageSize or DEFAULT_PAGE_SIZE
            body = compact(
                {
                    "searchText": (searchText or "").strip(),
                    "computerGroup": guid(computerGroup, "computerGroup") if computerGroup else None,
                    "pageNumber": number,
                    "pageSize": size,
                    "childOrganizations": bool(childOrganizations),
                    "showLastCheckIn": True,
                }
            )
            return page_result(await client.post("Computer/ComputerGetByAllParameters", body), number, size)

        return await run_tool("threatlocker_computers_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_computers_get(computerId: ComputerId) -> str:
        """Get one computer's details: name, group, organization, OS, mode, agent version and options."""

        async def action(client: ThreatLockerClient) -> Any:
            return await client.get("Computer/ComputerGetForEditById", {"computerId": guid(computerId, "computerId")})

        return await run_tool("threatlocker_computers_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_computers_get_checkins(
        computerId: ComputerId,
        pageNumber: PageNumber = None,
        pageSize: PageSize = None,
    ) -> str:
        """Get a computer's check-in history, newest first (heartbeats hidden)."""

        async def action(client: ThreatLockerClient) -> dict:
            number, size = pageNumber or 1, pageSize or DEFAULT_PAGE_SIZE
            body = {
                "computerId": guid(computerId, "computerId"),
                "pageNumber": number,
                "pageSize": size,
                "hideHeartbeat": True,
                "showTotalCount": True,
            }
            return page_result(await client.post("ComputerCheckin/ComputerCheckinGetByParameters", body), number, size)

        return await run_tool("threatlocker_computers_get_checkins", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_computer_groups_list(
        osType: Annotated[str | None, Field(description="Only groups for this numeric OS type id, as the portal uses it.")] = None,
        includeAllComputers: Annotated[bool | None, Field(description="Include the built-in All Computers group.")] = None,
        includeGlobal: Annotated[bool | None, Field(description="Include global (parent organization) groups.")] = None,
    ) -> str:
        """List computer groups with the computers in each."""

        async def action(client: ThreatLockerClient) -> dict:
            os_type = (osType or "").strip()
            if os_type and not os_type.isdigit():
                raise ValueError(f"osType must be the numeric OS type id (got {osType!r}).")
            params = compact(
                {
                    "OSType": int(os_type) if os_type else None,
                    "IncludeAllComputers": includeAllComputers,
                    "IncludeGlobal": includeGlobal,
                }
            )
            groups = rows(await client.get("ComputerGroup/ComputerGroupGetGroupAndComputer", params))
            return {"groups": groups, "count": len(groups)}

        return await run_tool("threatlocker_computer_groups_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_computer_groups_dropdown() -> str:
        """List computer groups as id / name pairs (lighter than threatlocker_computer_groups_list)."""

        async def action(client: ThreatLockerClient) -> dict:
            groups = rows(await client.get("ComputerGroup/ComputerGroupGetDropdownByOrganizationId"))
            return {"groups": groups, "count": len(groups)}

        return await run_tool("threatlocker_computer_groups_dropdown", client_factory, action)
