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
"""Ringfencing: read one policy, check eligibility, opt an organization in.

PRD-21247: the public Portal API has no endpoint to create or edit the content
of a ringfencing rule (which processes/network/storage a fenced application may
touch) -- the only org-wide "manage" action it exposes is opting the
organization into Ringfencing. These 3 tools are the full surface available.
"""

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import ThreatLockerClient
from ._common import MUTATING, READ_ONLY, ClientFactory, guid, run_tool

RingfencePolicyId = Annotated[str, Field(description="Ringfencing policy id (GUID).", min_length=1)]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_ringfence_get(ringfencePolicyId: RingfencePolicyId) -> str:
        """Get one Ringfencing policy's current data."""

        async def action(client: ThreatLockerClient) -> Any:
            return await client.get(f"RingfencePolicy/{guid(ringfencePolicyId, 'ringfencePolicyId')}")

        return await run_tool("threatlocker_ringfence_get", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def threatlocker_ringfence_eligibility() -> str:
        """Check whether the organization (and its computers) can be enrolled in Ringfencing."""

        async def action(client: ThreatLockerClient) -> Any:
            return (await client.post("RingfencePolicy/Eligibility", None)).data

        return await run_tool("threatlocker_ringfence_eligibility", client_factory, action)

    @mcp.tool(annotations=MUTATING)
    async def threatlocker_ringfence_opt_in() -> str:
        """Enroll the organization into Ringfencing."""

        async def action(client: ThreatLockerClient) -> dict:
            result = await client.post("RingfencePolicy/OptIn", None)
            return {"action": "opt_in", "result": result.data}

        return await run_tool("threatlocker_ringfence_opt_in", client_factory, action)
