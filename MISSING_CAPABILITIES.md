# TRUSTRAIL SECURITY CLOUD — MISSING CAPABILITIES

1. **Cryptographic Vault & Secret Rotation (`/lib/security/vault.ts`)**:
   - Authenticated `AES-256-GCM` encryption/decryption for connector credentials, cloud secrets, and SSO settings.
   - Envelope metadata (`keyVersion`, `iv`, `authTag`, `ciphertext`) and key rotation capability.
2. **Full Identity, Session & Account Lifecycle (`/api/v1/auth/*`, `/api/v1/team`)**:
   - Password reset / recovery token creation and verification.
   - Email verification workflow with signed/hashed verification token.
   - Login brute-force lockout & attempt tracking (`login_attempts`).
   - RFC 6238 TOTP MFA enrollment & code verification (`mfa/setup`, `mfa/verify`).
   - Session revocation (`revoked_tokens`) + session renewal (`auth/refresh`).
   - User profile update (`GET/PATCH /api/v1/auth/profile`) and admin user deactivation (`status = 'Disabled'`).
3. **API Key Enterprise Controls**:
   - Explicit granular scopes (`read`, `scan`, `write`, `admin`, `mcp`), optional `expires_at`, key rotation endpoint (`/api/v1/api-keys/[id]/rotate`), and failed API-key rate limiting.
4. **PostgreSQL Production Readiness & Backup Verification**:
   - Full PostgreSQL DDL (`/lib/db/postgres-schema.sql`), idempotent SQLite-to-PostgreSQL migration script (`/bin/migrate-sqlite-to-postgres.ts`), DB backup/restore verification endpoints (`/api/v1/recovery/backups`).
5. **Multi-Ecosystem & CI/CD Scanners**:
   - Lockfile parsers (`package-lock.json`, `requirements.txt`, `go.mod`, `pom.xml`), license risk classification, `.github/workflows/*.yml` security analyzer, SPDX 2.3 SBOM generator & validator (`/api/v1/projects/[id]/sbom`), and OCI Registry v2 public image manifest/digest inspector (`/api/v1/integrations/oci/inspect`).
6. **Real AWS SigV4 STS Client & Multi-Cloud Schemas**:
   - Zero-dependency cryptographic AWS Signature Version 4 signer executing live `sts.amazonaws.com` `GetCallerIdentity` when AWS env/role credentials exist, returning truthful `CREDENTIALS_REQUIRED` / `AUTHENTICATION_FAILED` otherwise; Azure & GCP connector definitions with persisted `cloud_resources` posture inventory.
7. **TLS Certificate & Multi-Hop SSRF Redirect Inspector**:
   - Direct `node:tls` socket handshake inspecting cert issuer, subject, SAN coverage, expiration days, and TLS version; safe hop-by-hop redirect validation re-checking DNS/IP at every hop.
8. **CI/CD Enforcement Modes & Remediation Verification Gate**:
   - Org-level `enforcement_mode` (`Observe` | `Recommend` | `Enforce`) integrated into `evaluatePolicies` and CI execution gates.
   - Tracked remediation runs (`/api/v1/remediation`) requiring verification tests/re-scan before marking findings `Resolved`.
9. **Observability, Background Job Queue & Notifications**:
   - Structured JSON logging, metrics endpoint (`/api/v1/system/metrics`), detailed `/api/health` readiness breakdown, `background_jobs` queue with retry & dead-letter status, and persisted `notification_deliveries` / `notification_preferences`.
10. **Deployment & Expanded Automated Test Suite**:
    - Production `Dockerfile`, updated `.env.example`, `DEPLOYMENT_GUIDE.md`, and comprehensive regression tests covering every security control, integration, API, CLI, SDK, and MCP flow.
