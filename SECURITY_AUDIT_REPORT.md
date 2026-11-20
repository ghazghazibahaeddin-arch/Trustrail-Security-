# TRUSTRAIL Security Cloud — Security Audit Report

**Audit Date:** 2026-11-20  
**Security Posture:** **Zero known critical/high release-blocking vulnerabilities in codebase.**

## 1. Security Controls Verified by Automated Unit & Integration Tests
| Control Domain | Mechanism Implemented | Verified Evidence | Status |
| :--- | :--- | :--- | :--- |
| **Connector & MFA Secret Vaulting** | `AES-256-GCM` authenticated envelope encryption (`lib/security/vault.ts`) with scrypt-derived 256-bit keys, versioned `keyVersion`, and `{orgId}:{connectorId}` / `{userId}` AAD binding | `tests/unit/security-hardening.test.ts` (AAD tamper rejected) & `vault-scanners-sbom-recovery.test.ts` (raw SQLite `connectors.config_json` verified ciphertext-only, key rotation v1->v2 verified) | **PASS** |
| **Brute-Force Lockout & Recovery** | 5 consecutive invalid login attempts lock account (`429 ACCOUNT_LOCKED`, 15m TTL via `login_attempts`); single-use SHA-256 password reset token clears lockout | `tests/integration/auth-mfa-lockout.test.ts` | **PASS** |
| **TOTP Multi-Factor Authentication** | RFC 4648 Base32 secret + RFC 6238 6-digit TOTP verification (`lib/security/crypto.ts`); login enforces `401 MFA_REQUIRED` / `INVALID_MFA_CODE` when enrolled | `tests/unit/security-hardening.test.ts` & `tests/integration/auth-mfa-lockout.test.ts` | **PASS** |
| **Session Lifecycle & Revocation** | `HttpOnly` + `SameSite=Lax` cookie & HMAC-SHA256 Bearer tokens with `jti` claim; `logout` and `refresh` insert prior `jti` into `revoked_tokens`; disabled users blocked immediately (`401` on active token, `403 ACCOUNT_DISABLED` on login) | `tests/integration/auth-mfa-lockout.test.ts` & live `:3000` (`POST /logout` -> `GET /metrics` `401`) | **PASS** |
| **Scoped API Keys & Rotation** | `tr_live_*` keys SHA-256 hashed, scoped (`read`,`scan`,`write`,`admin`), optional `expires_at`, atomic `/rotate` endpoint, failed auth IP rate limit | `tests/integration/auth-mfa-lockout.test.ts` (`read`-only key blocked `403 INSUFFICIENT_SCOPE` on scan; old key `401` after rotate) | **PASS** |
| **SSRF Defense-in-Depth** | `assertSafeExternalUrl` blocks private/loopback/CGNAT/link-local/metadata IPs, internal hostnames, embedded credentials, non-80/443 ports, DNS rebinding, and re-validates hop-by-hop redirects via `fetchWithSafeRedirects` | `tests/unit/security-hardening.test.ts` & `integrations-and-apikeys.test.ts` | **PASS** |
| **Multi-Tenant Isolation & RBAC** | `org_id` extracted solely from verified JWT/API-Key claims; `Viewer < Developer < Admin < Owner` hierarchy enforced in `requireAuth()` | `tests/integration/api-and-security.test.ts` | **PASS** |
| **Universal Secret Redaction** | `redactEvidenceSecrets()` masks AWS `AKIA*`, GitHub `gh*`, Stripe `sk_*`, Bearer headers, credentialed DB URIs, and quoted secrets across every scanner output | `tests/unit/engines.test.ts`, `mcp-cli-sdk.test.ts` | **PASS** |
| **Gated Remediation & IntentLock** | Canonical SHA-256 IntentLock auto-revokes altered change approvals (`409`); remediation closure blocked (`409 VERIFICATION_GATE_BLOCKED`) until verification scan & clean rescan pass | `tests/integration/api-and-security.test.ts` & `vault-scanners-sbom-recovery.test.ts` | **PASS** |
| **Immutable Hash-Chained Audit Ledger** | `appendAuditLog()` + `verifyAuditChain()` validate SHA-256 `prev_hash -> entry_hash` across all org events | `tests/integration/vault-scanners-sbom-recovery.test.ts` (`auditChain.valid === true`) | **PASS** |
| **SLSA Provenance Verification** | Timing-safe SHA-256 artifact digest (`SLSA 2`) and HMAC-SHA256 provenance verification (`SLSA 3`) | `tests/unit/security-hardening.test.ts` & `vault-scanners-sbom-recovery.test.ts` | **PASS** |

## 2. Production Operational Guidance
1. Always supply strong `TRUSTRAIL_SESSION_SECRET` and `TRUSTRAIL_VAULT_KEY` environment secrets in multi-instance/container deployments.
2. Mount a persistent volume at `TRUSTRAIL_DB_PATH` and `TRUSTRAIL_BACKUP_DIR`, or migrate to PostgreSQL (`lib/db/postgres-schema.sql`) + external Redis rate limiting when scaling horizontally.
