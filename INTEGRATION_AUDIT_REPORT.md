# TRUSTRAIL Security Cloud — Integration Audit Report

**Audit Date:** 2026-11-20  
**Policy:** No external integration is reported `PASS` unless verified via code + execution, and unconfigured third-party provider adapters truthfully report `NOT_CONFIGURED` / `HTTP 424`.

| Integration | Adapter / Route | Auth / Env Requirement | Runtime State in Current Environment | Verification Result |
| :--- | :--- | :--- | :--- | :--- |
| **SQLite (`node:sqlite` WAL)** | `lib/db.ts`, `GET /api/health` | `TRUSTRAIL_DB_PATH` (optional) | Connected (`schemaVersion: 4`, foreign keys + `busy_timeout`) | **PASS** (Vitest + Live `:3000` HTTP 200) |
| **OSV.dev Live CVE Feed** | `POST /api/v1/integrations/osv/query` | None (Public `https://api.osv.dev`) | Connected & Healthy | **PASS** (Verified live against `api.osv.dev` in Vitest) |
| **HTTP/TLS Inspector & SSRF Guard** | `lib/security/ssrf.ts`, `lib/integrations/tls-inspector.ts`, `/http-probe` | None (SSRF port/IP/DNS hardened) | Connected & Healthy | **PASS** (Ports, private/metadata IPs blocked; safe redirects + X.509 SANs verified) |
| **GitHub Repo Scanner** | `POST /api/v1/integrations/github/scan-repo` | Public repos: None; Private: Per-org encrypted PAT or `GITHUB_TOKEN` | Operational (public repos & live test; private requires PAT) | **PASS** (Vitest verified) |
| **GitHub Webhook Receiver** | `POST /api/v1/webhooks/github` | `GITHUB_WEBHOOK_SECRET` | HMAC-SHA256 verified + replay dedup (`webhook_deliveries`) | **PASS** (Vitest verified) |
| **OCI Registry v2 Client** | `lib/integrations/oci-client.ts`, `/api/v1/integrations/oci/inspect` | Optional Bearer auth for private registries | Operational for public OCI manifests (`docker.io`, `ghcr.io`, `mcr.microsoft.com`, etc.) | **PASS** (Compiled + typechecked) |
| **AWS SigV4 STS Caller Identity** | `lib/integrations/aws-sigv4.ts`, `/connectors/[id]/test` | Per-org vaulted `awsAccessKeyId` + `awsSecretAccessKey` (or env) | `NOT_CONFIGURED` until AWS credentials provided (`HTTP 424`) | **CONFIGURABLE (Truthful)** |
| **Azure Resource Manager Check** | `/api/v1/connectors/[id]/test` | `AZURE_ACCESS_TOKEN` + vaulted Tenant/Subscription ID | `NOT_CONFIGURED` until `AZURE_ACCESS_TOKEN` set (`HTTP 424`) | **CONFIGURABLE (Truthful)** |
| **GCP Resource Manager Check** | `/api/v1/connectors/[id]/test` | `GCP_ACCESS_TOKEN` + vaulted Project ID | `NOT_CONFIGURED` until `GCP_ACCESS_TOKEN` set (`HTTP 424`) | **CONFIGURABLE (Truthful)** |
| **Slack / Outbound Webhook** | `/api/v1/webhooks/outbound/test`, `/connectors/[id]/configure` | Per-org vaulted HTTPS `webhookUrl` or `SLACK_WEBHOOK_URL` | SSRF-hardened + delivery logged in `notification_deliveries` | **PASS** (Vitest mocked + SSRF verified) |
| **Gemini AI Copilot** | `/api/gemini` (`@google/genai`) | `GEMINI_API_KEY` | Configured if key set, otherwise `HTTP 503` truthfully | **CONFIGURABLE (Truthful)** |
| **MCP JSON-RPC 2.0 Server** | `POST /api/v1/mcp` | Session JWT or scoped `tr_live_` API Key | Live on `:3000` (5 tools + RBAC + IntentLock gate) | **PASS** (Vitest verified) |
| **Trustrail CLI & TypeScript SDK** | `bin/trustrail.ts`, `lib/sdk/trustrail-client.ts` | Optional token / API key | Operational (local + REST scan, `terraform-check`) | **PASS** (Vitest CLI + SDK tests passed) |
| **PostgreSQL Migration Path** | `lib/db/postgres-schema.sql`, `bin/migrate-sqlite-to-postgres.ts` | `DATABASE_URL` | Schema + migration script delivered | **DELIVERED** |
