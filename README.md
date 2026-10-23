# ThreatLocker MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [ThreatLocker](https://www.threatlocker.com)
Portal API. ThreatLocker is a zero-trust endpoint security platform: only approved software
runs on protected computers, and blocked users raise approval requests that the MSP reviews.
This server lets an AI agent read computers and their check-ins, computer groups, approval
requests, the unified audit log and child organizations. It is read-only.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored; every tool is listed from the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Threatlocker-Api-Key` | Yes | string | none | - | ThreatLocker API key | `your-api-key` |
| `X-Threatlocker-Organization-Id` | Yes | string | the key's own organization | GUID | Organization the calls act on (sent as `ManagedOrganizationId`) | `00000000-0000-0000-0000-000000000000` |
| `X-Threatlocker-Instance` | No | string | detected | letter, e.g. `g` | Portal instance in the API host `portalapi.{instance}.threatlocker.com`; a portal host name is also accepted | `g` |

Where to get them:

- In the ThreatLocker portal an administrator creates an **API user** and its API key; grant it
  read permissions for computers, approval requests, the unified audit and organizations.
- The organization id is shown in the portal for each organization; use the parent
  organization's id to work across its child organizations (`childOrganizations: true`).
- The instance is the letter in your portal address (for example `portal.g.threatlocker.com`
  -> `g`). When it is not sent, the server tries each instance once and remembers which one
  accepts the key (only that letter is kept, keyed by a hash of the key).

How credentials are sent to ThreatLocker: every call goes to
`https://portalapi.{instance}.threatlocker.com/portalapi/...` with the raw key in the
`Authorization` header (no `Bearer` prefix) and the organization id in `ManagedOrganizationId`.

A request to `/mcp` without the key gets HTTP 401; an organization id that is not a GUID or an
unusable instance value does not block the request, and tools return `invalid_argument` instead.

## Tools

All tools return a JSON string and are read-only. Paged tools take `pageNumber` (from 1) and
`pageSize` (default 25) and return `{items, count, page, page_size, total, has_more, offset,
next_offset}`. They also take `offset` (record position from 0, overrides `pageNumber`): pass
`next_offset` as `offset` for the next records. ThreatLocker pages by number only, so when a page
is cut to fit the response size limit the rest of it is on no other page; `next_offset` then
starts right after the last record returned, and the tool reads the page that holds it.
Computer, group, organization and approval request ids are GUIDs.

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `threatlocker_navigate` | Describe the tools of one area (changes nothing) | **domain** (`computers`, `computer_groups`, `approval_requests`, `audit_log`, `organizations`) |
| `threatlocker_status` | Check the connection (key, organization, instance) and list the tool areas | - |
| `threatlocker_computers_list` | List protected computers: name, group, organization, mode, version, last check-in | searchText, computerGroup, pageNumber, pageSize, childOrganizations |
| `threatlocker_computers_get` | One computer's details | **computerId** |
| `threatlocker_computers_get_checkins` | A computer's check-in history, newest first (heartbeats hidden) | **computerId**, pageNumber, pageSize |
| `threatlocker_computer_groups_list` | Computer groups with their computers | osType (numeric id), includeAllComputers, includeGlobal |
| `threatlocker_computer_groups_dropdown` | Computer groups as id / name pairs | - |
| `threatlocker_approvals_list` | Approval requests by status, newest first | status (Pending by default, Approved, Rejected / Denied, Not Learned, Added To Application, Escalated, Self Approved), pageNumber, pageSize, searchText, childOrganizations |
| `threatlocker_approvals_get` | One approval request: requester, computer, file, hash, certificate, justification | **approvalRequestId** |
| `threatlocker_approvals_pending_count` | Count of pending approval requests | - |
| `threatlocker_approvals_get_permit_application` | What approving a request would permit | **approvalRequestId** |
| `threatlocker_audit_search` | Search the unified audit (what ran or was blocked); default window the last 24 h. `total` is given only on the last page that has rows (an empty page past the end has none): the API's count while more pages exist is not a total | searchText (file path contains), startDate, endDate, pageNumber, pageSize, childOrganizations, hostname, actionType |
| `threatlocker_audit_get` | One audit entry in full; without sourceTableId, tables 1 then 2 are tried (search rows come from table 1) | eActionLogId (from a search row), sourceTableId (1-4), actionLogId (deprecated alias) |
| `threatlocker_audit_file_history` | Audit history of one file on one computer | **fullPath**, hostname or computerId, sourceTableId, pageNumber, pageSize |
| `threatlocker_organizations_list_children` | Child (customer) organizations | searchText, pageNumber, pageSize |
| `threatlocker_organizations_get_auth_key` | The organization's agent install key (a secret) | - |
| `threatlocker_organizations_for_move_computers` | Organizations computers may be moved to | - |

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "ThreatLocker returned HTTP 401 for Computer/ComputerGetByAllParameters", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`. Every call is a read, so 429, 5xx and network errors are
retried with backoff.

## Run locally

```bash
uv sync
uv run python -m threatlocker_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t threatlocker-mcp:dev .
docker run --rm -p 8080:8080 threatlocker-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). Credentials are never read
from the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Threatlocker-Api-Key: your-api-key" \
  -H "X-Threatlocker-Organization-Id: 00000000-0000-0000-0000-000000000000" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# pending approval requests
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Threatlocker-Api-Key: your-api-key" \
  -H "X-Threatlocker-Organization-Id: 00000000-0000-0000-0000-000000000000" \
  -H "X-Threatlocker-Instance: g" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"threatlocker_approvals_list","arguments":{"status":"Pending","pageSize":10}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool count (17).** Kept as is because the tool names are an existing contract.
- **Read-only.** No tool approves, denies or changes anything in ThreatLocker.
- **Install key.** `threatlocker_organizations_get_auth_key` returns a secret that lets anyone
  enroll computers; its description tells the agent to call it only on explicit request and
  not to repeat it elsewhere.
- **API contract.** Endpoints, parameters and body fields follow ThreatLocker's published
  Portal API specification (`/swagger/public/swagger.json` on the API host). Ids are sent as
  GUIDs, the group OS type as its numeric id, and the audit search window defaults to the
  last 24 hours.
- **No interactive prompts.** Older versions asked the user for a search term, a status or a
  date range mid-call, which a stateless gateway cannot relay; defaults apply instead.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
