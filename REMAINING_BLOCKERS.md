# TRUSTRAIL Security Cloud — Remaining Blockers & External Dependencies

**Release-Blocking Code Defects:** **0**  
**Release-Blocking Critical/High Security Vulnerabilities:** **0**

## External Integration & Infrastructure Items Requiring Environment Provisioning
The following items remain configurable at customer deployment time and are truthfully reported in the UI and `/api/v1/connectors` (`NOT_CONFIGURED` / `HTTP 424`) when credentials are omitted:

| Item | Type | Current State in Sandbox | Required Action Before Enabling in Production |
| :--- | :--- | :--- | :--- |
| **1. GitHub Private Repo Sync** (`GITHUB_TOKEN`) | External Credential | Public repos operational; private repos require per-org vaulted PAT or `GITHUB_TOKEN`. | Supply GitHub App token / PAT (`repo`, `security_events` read) in Connector settings or env. |
| **2. GitHub Live Webhook Deliveries** (`GITHUB_WEBHOOK_SECRET`) | External Credential | HMAC-SHA256 + replay dedup verified in Vitest with test secret. | Set `GITHUB_WEBHOOK_SECRET` and point GitHub webhook to `/api/v1/webhooks/github`. |
| **3. AWS Live STS / IAM Polling** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) | External Credential | Live SigV4 STS `GetCallerIdentity` adapter wired; returns `424 NOT_CONFIGURED` until creds saved. | Save read-only AWS credentials via encrypted Connector vault or runtime env. |
| **4. Azure & GCP Cloud Account Polling** (`AZURE_ACCESS_TOKEN`, `GCP_ACCESS_TOKEN`) | External Credential | Adapter checks implemented; returns `424 NOT_CONFIGURED` until tokens supplied. | Supply `AZURE_ACCESS_TOKEN` / `GCP_ACCESS_TOKEN` and tenant/project metadata. |
| **5. Slack / Outbound Alert Webhooks** (`SLACK_WEBHOOK_URL`) | External Credential | SSRF-hardened delivery + `notification_deliveries` logging verified; returns `424` until configured. | Save HTTPS Slack/Discord webhook URL via Connector settings or env. |
| **6. Multi-Replica Secrets & DB Scale** | Runtime Infrastructure | Production `Dockerfile` + `lib/db/postgres-schema.sql` + `bin/migrate-sqlite-to-postgres.ts` ready. | Set explicit `TRUSTRAIL_SESSION_SECRET` and `TRUSTRAIL_VAULT_KEY`; migrate SQLite -> PostgreSQL + Redis for multi-node active-active scaling. |
