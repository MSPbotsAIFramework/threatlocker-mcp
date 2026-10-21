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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import ThreatLockerClient, ThreatLockerCredentials
from .config import Settings

HEADER_API_KEY = "X-Threatlocker-Api-Key"
HEADER_ORGANIZATION_ID = "X-Threatlocker-Organization-Id"
HEADER_INSTANCE = "X-Threatlocker-Instance"

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_INSTANCE = re.compile(r"^[a-z]{1,10}$")
_INSTANCE_IN_HOST = re.compile(r"^(?:https?://)?(?:beta)?portal(?:api)?\.([a-z]{1,10})\.threatlocker\.com", re.IGNORECASE)

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[ThreatLockerCredentials | None] = contextvars.ContextVar(
    "threatlocker_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("threatlocker_request_id", default="-")

INSTRUCTIONS = (
    "ThreatLocker is a zero-trust endpoint security platform: only approved "
    "software may run on protected computers. When something is blocked, the "
    "user can raise an approval request that an MSP technician reviews. This "
    "server is read-only.\n"
    "Usage:\n"
    "- Machines: threatlocker_computers_list(searchText) -> "
    "threatlocker_computers_get / threatlocker_computers_get_checkins "
    "(computer ids are GUIDs).\n"
    "- Pending work: threatlocker_approvals_pending_count, "
    "threatlocker_approvals_list(status) -> threatlocker_approvals_get and "
    "threatlocker_approvals_get_permit_application (what approving would allow).\n"
    "- Why was something blocked or allowed: threatlocker_audit_search "
    "(date window, default last 24 h; searchText matches the file path, "
    "hostname narrows to one computer) -> threatlocker_audit_get(eActionLogId); "
    "threatlocker_audit_file_history for one file on one computer.\n"
    "- Structure: threatlocker_computer_groups_list, "
    "threatlocker_organizations_list_children.\n"
    "- Lists page with pageNumber + pageSize and return has_more.\n"
    "threatlocker_organizations_get_auth_key returns the organization's agent "
    "install key, a secret: call it only when the user explicitly asks and "
    "never paste it anywhere else."
)


def get_client_from_context() -> ThreatLockerClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return ThreatLockerClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def normalize_instance(value: str) -> str | None:
    """The instance letter from 'g', 'G' or a portal / API host name; None if unusable."""
    text = value.strip().lower()
    if _INSTANCE.match(text):
        return text
    match = _INSTANCE_IN_HOST.match(text)
    return match.group(1).lower() if match else None


class GatewayCredentialsMiddleware:
    """Reads the ThreatLocker headers on /mcp requests into the request context; 401 without a key.

    Malformed organization id / instance values do not block the request (tools/list
    must work with any values); tools report them instead.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        api_key = _clean(request.headers.get(HEADER_API_KEY))
        organization_id = _clean(request.headers.get(HEADER_ORGANIZATION_ID))
        instance_raw = _clean(request.headers.get(HEADER_INSTANCE))

        if not api_key:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Send the ThreatLocker API key in {HEADER_API_KEY}",
                    "required_headers": [HEADER_API_KEY, HEADER_ORGANIZATION_ID],
                    "optional_headers": [HEADER_INSTANCE],
                },
                status_code=401,
            )(scope, receive, send)
            return
        errors: list[str] = []
        if organization_id and not _GUID.match(organization_id):
            errors.append(f"{HEADER_ORGANIZATION_ID} must be a GUID")
            organization_id = None
        instance = normalize_instance(instance_raw) if instance_raw else None
        if instance_raw and not instance:
            errors.append(f"{HEADER_INSTANCE} must be the portal instance letter, e.g. g")

        credentials = ThreatLockerCredentials(
            api_key=api_key,
            organization_id=organization_id,
            instance=instance,
            header_error="; ".join(errors) or None,
        )
        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(credentials)
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = FastMCP(
        name="threatlocker-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], ThreatLockerClient | None] = get_client_from_context

    from .tools import approvals, audit, computers, navigation, organizations

    for module in (navigation, computers, approvals, audit, organizations):
        module.register(mcp, client_factory)

    return mcp
