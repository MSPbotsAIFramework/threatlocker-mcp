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
"""tools/list snapshot and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from threatlocker_mcp.api_client import ThreatLockerError
from threatlocker_mcp.server import INSTRUCTIONS, create_mcp_server

# Tool names are a public contract: existing agents and tenant connections
# depend on them. Changing this snapshot is a breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "threatlocker_navigate": {"domain"},
    "threatlocker_status": set(),
    "threatlocker_computers_list": set(),
    "threatlocker_computers_get": {"computerId"},
    "threatlocker_computers_get_checkins": {"computerId"},
    "threatlocker_computer_groups_list": set(),
    "threatlocker_computer_groups_dropdown": set(),
    "threatlocker_approvals_list": set(),
    "threatlocker_approvals_get": {"approvalRequestId"},
    "threatlocker_approvals_pending_count": set(),
    "threatlocker_approvals_get_permit_application": {"approvalRequestId"},
    "threatlocker_audit_search": set(),
    "threatlocker_audit_get": set(),
    "threatlocker_audit_file_history": {"fullPath"},
    "threatlocker_organizations_list_children": set(),
    "threatlocker_organizations_get_auth_key": set(),
    "threatlocker_organizations_for_move_computers": set(),
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_are_stable(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_every_tool_is_read_only(tools, name):
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is True


def test_auth_key_tool_warns_it_is_a_secret(tools):
    description = tools["threatlocker_organizations_get_auth_key"].description
    assert "secret" in description.lower()
    assert "explicitly asks" in description


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500


@pytest.mark.parametrize(
    "status,code,retryable",
    [
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (440, "unauthorized", False),
        (404, "not_found", False),
        (400, "invalid_argument", False),
        (417, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (0, "upstream_error", True),
    ],
)
def test_error_envelope(status, code, retryable):
    envelope = json.loads(ThreatLockerError(status, "boom").to_envelope())
    assert envelope == {"error": {"code": code, "message": "boom", "retryable": retryable}}


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("threatlocker_status", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"


def test_navigate_needs_no_credentials():
    content, _ = asyncio.run(create_mcp_server().call_tool("threatlocker_navigate", {"domain": "computer_groups"}))
    assert json.loads(content[0].text)["tools"] == ["threatlocker_computer_groups_list", "threatlocker_computer_groups_dropdown"]


@pytest.mark.parametrize(
    "name",
    [
        "threatlocker_computers_list",
        "threatlocker_computers_get_checkins",
        "threatlocker_approvals_list",
        "threatlocker_audit_search",
        "threatlocker_audit_file_history",
        "threatlocker_organizations_list_children",
    ],
)
def test_page_size_capped_at_200(tools, name):
    schema = tools[name].inputSchema["properties"]["pageSize"]
    maxima = [schema.get("maximum")] + [option.get("maximum") for option in schema.get("anyOf", [])]
    assert 200 in maxima and not any(m and m > 200 for m in maxima)
