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
"""Shared argument types, paging helpers and the error-handling wrapper."""

import logging
import re
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import Page, ThreatLockerClient, ThreatLockerError

logger = logging.getLogger("threatlocker_mcp.tools")

ClientFactory = Callable[[], ThreatLockerClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
LOCAL = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)

NOT_CONFIGURED = error_envelope(
    "not_configured",
    "ThreatLocker credentials are missing for this request (X-Threatlocker-Api-Key, X-Threatlocker-Organization-Id).",
    False,
)

DEFAULT_PAGE_SIZE = 25

PageNumber = Annotated[int | None, Field(description="Page number, from 1 (default 1).", ge=1)]
PageSize = Annotated[int | None, Field(description=f"Results per page, 1-200 (default {DEFAULT_PAGE_SIZE}).", ge=1, le=200)]
SearchText = Annotated[str | None, Field(description="Text to search for.")]
ChildOrganizations = Annotated[bool | None, Field(description="Also include child organizations' records.")]
Guid = Annotated[str, Field(description="GUID.", min_length=1)]

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None}


def guid(value: str | None, name: str) -> str:
    text = (value or "").strip()
    if not _GUID.match(text):
        raise ValueError(f"{name} must be a GUID such as 00000000-0000-0000-0000-000000000000 (got {value!r}).")
    return text


def rows(payload: Any) -> list:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("items", "data", "results", "groups", "organizations", "logs"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


def page_result(page: Page, number: int, size: int) -> dict:
    """Items plus paging: {items, count, page, page_size, total, has_more}."""
    items = rows(page.data)
    meta = page.pagination or {}
    total = meta.get("totalItems")
    if total is None and isinstance(page.data, dict):
        total = page.data.get("totalItems")
    if isinstance(meta.get("totalPages"), int) and isinstance(meta.get("currentPage"), int):
        more = meta["currentPage"] < meta["totalPages"]
    elif isinstance(total, int):
        more = number * size < total
    else:
        more = len(items) >= size
    return compact(
        {
            "items": items,
            "count": len(items),
            "page": number,
            "page_size": size,
            "total": total,
            "has_more": more,
        }
    )


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[ThreatLockerClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    started = time.monotonic()
    try:
        result = await action(client)
    except ThreatLockerError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if result is None:
        result = {"result": None, "note": "ThreatLocker returned an empty response."}
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
