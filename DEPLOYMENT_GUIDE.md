# TRUSTRAIL Security Cloud — Production Deployment Guide

## 1. Prerequisites & Runtime Stack
- **Runtime:** Node.js `22.x` (`node:sqlite` built-in WAL database) or Docker Engine 24+
- **Framework:** Next.js `15.4.9` (`output: 'standalone'`)
- **Database Migration Target (Optional Horizontal Scale):** PostgreSQL 15+ (`lib/db/postgres-schema.sql` and `bin/migrate-sqlite-to-postgres.ts`)

## 2. Required & Optional Environment Variables
Configure secrets via your orchestrator / Secret Manager (see `.env.example`):

| Variable | Required | Purpose |
| :--- | :--- | :--- |
| `TRUSTRAIL_SESSION_SECRET` | **Yes (Prod)** | 32+ char HMAC-SHA256 signing secret for session JWTs and Trust Center receipts. |
| `TRUSTRAIL_VAULT_KEY` | **Yes (Prod)** | Master AES-256-GCM encryption key for connector credentials & TOTP MFA secrets. |
| `TRUSTRAIL_VAULT_KEY_VERSION` | Recommended (`1`) | Active key version identifier (`1`, `2`, ...). |
| `TRUSTRAIL_VAULT_PREVIOUS_KEY` | During Rotation | Previous master key retained during `POST /api/v1/connectors/rotate-secrets` transitions. |
| `TRUSTRAIL_DB_PATH` | Optional | Persistent path for SQLite database (e.g. `/var/lib/trustrail/trustrail.db`). |
| `TRUSTRAIL_BACKUP_DIR` | Optional | Persistent directory for SHA-256 checksummed recovery snapshots. |
| `GEMINI_API_KEY` | Optional | Server-side key for `/api/gemini` AI Copilot & Remediation guidance. |
| `TRUSTRAIL_ATTESTATION_SECRET` | Optional | Shared HMAC-SHA256 key for SLSA Level 3 provenance attestation checks. |
| `GITHUB_TOKEN`, `GITHUB_WEBHOOK_SECRET` | Optional | Live GitHub private repo scanning and HMAC-SHA256 webhook verification. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_ROLE_ARN`, `AWS_EXTERNAL_ID` | Optional | Live AWS SigV4 STS `GetCallerIdentity` verification & IAM Role assumption. |
| `AZURE_ACCESS_TOKEN`, `GCP_ACCESS_TOKEN`, `SLACK_WEBHOOK_URL` | Optional | Live Azure/GCP API checks and Slack/Discord webhook alerting. |

## 3. Container Build & Run (`Dockerfile`)
The included multi-stage `/Dockerfile` builds the standalone production server running under an unprivileged `trustrail` user (`UID 1001`) with an integrated `/api/health` container health check:

```bash
docker build -t trustrail-security-cloud:latest .
docker run -d \
  --name trustrail \
  -p 3000:3000 \
  -v trustrail_data:/var/lib/trustrail \
  -e TRUSTRAIL_SESSION_SECRET="$(openssl rand -hex 32)" \
  -e TRUSTRAIL_VAULT_KEY="$(openssl rand -hex 32)" \
  -e TRUSTRAIL_VAULT_KEY_VERSION=1 \
  -e TRUSTRAIL_DB_PATH=/var/lib/trustrail/trustrail.db \
  -e TRUSTRAIL_BACKUP_DIR=/var/lib/trustrail/backups \
  trustrail-security-cloud:latest
```

## 4. Direct Node.js Production Deployment
```bash
npm ci
npm run typecheck
npm test
npm run build
npm run start
```

## 5. Vault Key Rotation Runbook
1. Set `TRUSTRAIL_VAULT_PREVIOUS_KEY` to the current `TRUSTRAIL_VAULT_KEY`.
2. Set `TRUSTRAIL_VAULT_KEY` to a newly generated 32+ byte secret and increment `TRUSTRAIL_VAULT_KEY_VERSION=2`.
3. Restart the service cleanly.
4. Execute `POST /api/v1/connectors/rotate-secrets` (or click **Rotate Vault Keys** in **Settings**). All encrypted envelopes re-wrap under the active version without downtime.

## 6. SQLite to PostgreSQL Migration (Optional Multi-Replica Scale)
1. Provision PostgreSQL and apply `/lib/db/postgres-schema.sql`.
2. Set `DATABASE_URL="postgres://..."` and run `npx tsx bin/migrate-sqlite-to-postgres.ts`.
