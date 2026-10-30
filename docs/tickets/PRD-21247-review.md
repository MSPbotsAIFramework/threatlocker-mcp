# PRD-21247 · Code review

## Round 1 · 2026-10-30 · reviewed dev/PRD-21247 @ 2b428d2 (base main @ 8bdf9c5)

Verdict: changes requested

### Findings

1. [must-fix] `src/threatlocker_mcp/api_client.py:232-237` (and the stale comment at `:232-233`) —
   `ThreatLockerClient.request()` treats every call as safely retryable
   (`retryable = status in (0, 429) or status >= 500`, up to `_MAX_RETRIES = 2` with backoff) with
   no distinction between read and write calls. Before this ticket that was true by construction —
   the comment says "Every call this server makes is a read (searches are POSTs with a filter
   body), so all of them may be retried." This ticket adds the connector's first 4 real mutating
   POSTs (`ApprovalRequestAuthorizeForPermitById`, `ApprovalRequestUpdateForReject`,
   `ApprovalRequestUpdateForIgnore`, `RingfencePolicy/OptIn`), which go through the exact same
   `request()` path and are therefore auto-retried on a transient `5xx`/`429`/timeout exactly like
   a read. Concretely: if ThreatLocker processes an approve/reject/ignore/opt-in successfully but
   the response is lost to a timeout or a transient `503`, the client automatically re-sends the
   identical mutating POST. ThreatLocker's second response to an already-resolved request is an
   upstream error (the tech design's own "Non-functional → Idempotency" section says acting twice
   on an already-resolved request "is expected to come back as an upstream error"), so the tool
   would report a failure to the agent/user even though the action had already succeeded — a false
   negative on a security-relevant action (approving/denying software execution, enrolling an org
   in Ringfencing) that the agent or a human may then "retry" again at the application layer,
   compounding the confusion. The tech design's idempotency discussion only reasons about *callers*
   retrying the tool (hence `idempotentHint=False` on `MUTATING`); it never revisits the transport
   layer's own silent internal retry, which fires regardless of that hint. Comment is now false and
   nothing in this diff revisits the retry predicate for the 4 new write paths. No test exercises
   this (checked `tests/` for `retry`/`retryable`/`_MAX_RETRIES`: only hits are for the unrelated
   `error_envelope`/pagination retry-hint logic).
   Fix: either make `retryable` false for the 4 mutating calls (e.g. thread an `idempotent: bool`
   through `ThreatLockerClient.post`/`.request`, defaulting to the current read behavior and set to
   `False` for approve/reject/ignore/opt-in), or otherwise prevent an unacknowledged write from
   being silently resent — and update the now-inaccurate comment either way.

2. [suggestion] `src/threatlocker_mcp/tools/approvals.py:14` — module docstring still reads
   "Approval requests: users asking for blocked software to be allowed (read-only here)." This file
   is no longer read-only after this ticket (3 of its 7 tools mutate). Not a behavior issue, just a
   stale comment this diff should have touched while it was already editing the file.

3. [suggestion] `docs/tickets/PRD-21247.md:464` — the Self-test section's Chinese-character scan
   claims "no matches" but the file itself contains one Chinese-language quote (`"有就跑"`, quoted
   from the skill's own convention doc) two lines above that claim. It is in ticket documentation,
   not source/README/tool-facing text, so it doesn't reach an agent or a human reading the
   connector — but the stated evidence ("no matches") is factually off by one, and MCP repos are
   supposed to be English-only end to end. Low cost to fix: rephrase that one sentence in English
   without quoting the Chinese phrase.

### Everything else checked, no issue found

- Scope matches the tech design's Change list file-for-file; no out-of-scope files touched.
- Reuse: new tools go through the existing `ThreatLockerClient.get/post`, `run_tool`,
  `error_envelope`, `guid()` — no new HTTP client, no duplicated retry/backoff logic, no new
  third-party dependency. `threatlocker_approvals_get`'s existing call pattern
  (`ApprovalRequest/ApprovalRequestGetById` with a query-param `approvalRequestId`) is reused
  verbatim by reject/ignore's get-then-post, not reimplemented.
- GUID validation (`guid()`) runs before any HTTP call in all 6 new tools, confirmed by
  `test_malformed_approval_request_id_never_calls_api` / `test_get_malformed_id_never_calls_api`
  asserting `rec.requests == []` — matches AC4/AC "invalid GUID, no partial state change".
  `ApprovalRequestGetById` returning 404 is checked before reject/ignore ever POST
  (`test_reject_unknown_request_never_calls_update_for_reject`,
  `test_ignore_unknown_request_never_calls_update_for_ignore`) — AC4's "no partial state change"
  holds.
  Missing-header path (`AC8`) reuses the existing `NOT_CONFIGURED` envelope via `run_tool`, not a
  new error shape — confirmed by `test_new_tools_without_credentials_return_not_configured` in both
  new test files.
- Multi-tenant isolation (AC9 / OWASP API1 BOLA anchor): `test_two_organizations_never_cross_managed_organization_id`
  in both new test files asserts the `ManagedOrganizationId` header on each call matches that
  call's own credentials, never the other tenant's — credentials are per-request
  (`ThreatLockerClient.__init__`), nothing is cached by org id (only the instance-detection cache,
  keyed by a hash of the API key, confirmed at `api_client.py:68-75`).
  Every success result names the id acted on and the action (AC10), confirmed by
  `test_success_results_name_id_and_action` in both files.
- `README.md`'s Connector section is byte-identical to `origin/main` (diffed directly,
  `reference/readme-connector-section.md` compliance unaffected by this change) — the Tools table,
  auth-header note and Delivery notes updates are all outside that section.
- Chinese-character scan across `src/`, `tests/`, `README.md`: no matches (only the ticket-doc hit
  in finding 3).
- Gate: re-ran `uv run pytest` myself on `dev/PRD-21247 @ 2b428d2` — 269 passed, 0 failed, matching
  the `[DEV]` stub's claim. No migrations (this repo has none).
- `EXPECTED_TOOLS` in `tests/test_tools.py` extended to all 23 tools (17 unchanged + 6 new);
  splitting `test_every_tool_is_read_only` into `test_every_other_tool_is_read_only` +
  `test_mutating_tools_are_marked_as_such` keeps both halves of the original guarantee checked
  rather than weakening it.
- No new third-party dependency, no parameter stacking (all 6 new tools take only GUIDs/short
  strings, matching every existing tool's shape), no dead code introduced or left behind.

### Fixes (round 1)

1. [must-fix, fixed] `src/threatlocker_mcp/api_client.py` — threaded `idempotent: bool = True`
   through `ThreatLockerClient.request()`/`.post()`. The retry predicate is now
   `retryable = idempotent and (status in (0, 429) or status >= 500)`, so the default (reads,
   including POST-shaped searches) is unchanged, while a non-idempotent call surfaces the first
   failure instead of being silently resent. The 4 mutating call sites now pass
   `idempotent=False`: `src/threatlocker_mcp/tools/approvals.py` (`approve`, `reject`, `ignore`)
   and `src/threatlocker_mcp/tools/ringfence.py` (`opt_in`). Replaced the stale "every call is a
   read" comment with one that states the idempotent/non-idempotent split and why. Added
   regression coverage: `tests/test_api_client.py` (`test_non_idempotent_post_is_not_retried_on_5xx`,
   `test_non_idempotent_post_is_not_retried_on_timeout`,
   `test_idempotent_post_default_still_retries_on_5xx` — the last one pins down that the default
   path is unchanged), `tests/test_approvals_write.py`
   (`test_transient_failure_on_the_mutating_call_is_not_retried`, parametrized over
   approve/reject/ignore), `tests/test_ringfence.py` (`test_opt_in_transient_failure_is_not_retried`).
   Commit: `a87a958` (synced with `main @ 8bdf9c5`, unchanged since round 1 — no merge needed).
   Re-ran gates on `dev/PRD-21247 @ a87a958`: `uv run pytest` 276/276 (269 baseline + 7 new, 0
   failed, 0 regressions); local smoke (`uv run python -m threatlocker_mcp`) — `/health` 200,
   `tools/list` with a placeholder key returns all 23 tools (the 4 mutating ones now show
   `idempotentHint: false` in their response, matching the tool annotations already in place),
   missing-header request 401; Chinese-character scan of `src/`, `tests/`, `README.md` clean
   (0 matches); `README.md`'s MSPbots Connector section (lines 17-87) still byte-identical to
   `reference/readme-connector-section.md`; `gitleaks` not installed in this environment, skipped
   (same as round 1).
2. [suggestion, not changed] `src/threatlocker_mcp/tools/approvals.py:14` module docstring — left
   as-is. Out of scope for this round: only the must-fix (finding 1) is addressed; a drive-by
   wording fix is not a must-fix and risks touching unrelated lines mid-rework.
3. [suggestion, not changed] `docs/tickets/PRD-21247.md:464` Self-test wording — left as-is for
   the same reason. The main ticket document is frozen and is not edited during a review-fix
   round regardless; both suggestions remain open for whoever next touches these files.

Status: changes requested → fixes applied above, ready for round 2 review. Scope of this round:
only finding 1 (must-fix). Findings 2-3 (suggestions) intentionally left open.
