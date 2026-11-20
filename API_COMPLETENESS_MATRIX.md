# TRUSTRAIL Security Cloud — API Completeness Matrix

**OpenAPI 3.1 Spec Endpoint:** `GET /api/v1/openapi.json`  
**Total Documented & Implemented Paths:** **63** (100% route-file parity verified by `tests/integration/mcp-cli-sdk.test.ts` and live `GET /api/v1/openapi.json` on port 3000)

| Endpoint | Methods | Auth Required | Minimum Role / Scope | Validation / Controls | Verification Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/health` | `GET` | Public | None | DB WAL + `audit_logs` + job queue readiness | **PASS** (Live `:3000` HTTP 200, `schemaVersion: 4`) |
| `/api/gemini` | `POST` | Yes | Viewer | Zod (`GeminiRequestSchema`), rate limit 20/min | **PASS** (Vitest + Live `:3000`) |
| `/api/v1/openapi.json` | `GET` | Public | None | OpenAPI 3.1 JSON (63/63 routes) | **PASS** (Live `:3000` HTTP 200, 63 paths) |
| `/api/v1/auth/session` | `GET` | Cookie/Bearer | Optional | Includes `emailVerified`, `mfaVerified`, `scopes` | **PASS** |
| `/api/v1/auth/login` | `POST` | Public | None | Lockout (`429 ACCOUNT_LOCKED`), Disabled (`403`), TOTP MFA (`401 MFA_REQUIRED`) | **PASS** (Vitest + Live `:3000` HTTP 200) |
| `/api/v1/auth/register` | `POST` | Public | None | Atomic DB tx, issues `email_verify` token | **PASS** (Vitest verified) |
| `/api/v1/auth/logout` | `POST` | Public/Token | None | Inserts JWT `jti` into `revoked_tokens` | **PASS** (Vitest + Live `:3000`: post-logout 401) |
| `/api/v1/auth/refresh` | `POST` | Yes | Viewer | Rotates session JWT and revokes prior `jti` | **PASS** (Vitest verified) |
| `/api/v1/auth/profile` | `GET, PATCH` | Yes | Viewer | Profile update + current-password verified password rotation | **PASS** |
| `/api/v1/auth/verify-email` | `POST` | Public/Token | None / Resend | Single-use SHA-256 token verification | **PASS** (Vitest verified) |
| `/api/v1/auth/forgot-password` | `POST` | Public | None | Single-use 15m reset token + rate limit | **PASS** (Vitest verified) |
| `/api/v1/auth/reset-password` | `POST` | Public | None | Resets password & clears brute-force lockout | **PASS** (Vitest verified) |
| `/api/v1/auth/mfa/setup` | `POST` | Yes | Viewer | Generates RFC 4648 Base32 secret, encrypted AES-256-GCM | **PASS** (Vitest verified) |
| `/api/v1/auth/mfa/verify` | `POST, DELETE` | Yes | Viewer | RFC 6238 6-digit TOTP check / disable MFA | **PASS** (Vitest verified) |
| `/api/v1/auth/switch-org` | `POST` | Yes | Viewer | Verifies active org membership (`403` otherwise) | **PASS** (Vitest verified) |
| `/api/v1/api-keys` | `GET, POST` | Yes | Developer | Scopes (`read`,`scan`,`write`,`admin`), TTL (`expiresInDays`), SHA-256 hash | **PASS** (Vitest verified) |
| `/api/v1/api-keys/{id}` | `DELETE` | Yes | Developer / Admin | Revokes key (`401` immediately) | **PASS** (Vitest verified) |
| `/api/v1/api-keys/{id}/rotate` | `POST` | Yes | Developer / Admin | Atomic revoke old + issue rotated key | **PASS** (Vitest verified) |
| `/api/v1/organizations` | `GET, POST, PATCH` | Yes | Viewer / Admin | `enforcementMode` (`Observe`/`Recommend`/`Enforce`), retention | **PASS** |
| `/api/v1/projects` | `GET, POST` | Yes | Viewer / Developer | Tenant-scoped CRUD | **PASS** |
| `/api/v1/projects/{id}` | `GET, PATCH, DELETE` | Yes | Viewer / Dev / Admin | IDOR `404` across orgs | **PASS** (Vitest verified) |
| `/api/v1/projects/{id}/sbom` | `GET, POST` | Yes | Viewer (`read`) / Dev (`write`) | CycloneDX 1.5 / SPDX 2.3 + validator + SHA-256/HMAC SLSA 2/3 attestation | **PASS** (Vitest verified) |
| `/api/v1/scans` | `GET, POST` | Yes | Viewer (`read`) / Dev (`scan`) | SAST, Secrets, npm/lockfile/PyPI/Go/Maven, GHA Workflows, Terraform, Dockerfile | **PASS** (Vitest verified) |
| `/api/v1/findings` | `GET` | Yes | Viewer | Parameterized filters + explainable Risk Engine sort | **PASS** |
| `/api/v1/findings/{id}` | `GET, PATCH` | Yes | Viewer / Developer | Status & evidence updates | **PASS** |
| `/api/v1/remediation` | `GET, POST, PATCH` | Yes | Viewer (`read`) / Dev (`write`) | Tracked patch -> `run_verification` -> `rescan_and_resolve` (`409` gate) | **PASS** (Vitest + Live `:3000` HTTP 200) |
| `/api/v1/graph` | `GET` | Yes | Viewer | Asset nodes & edges | **PASS** |
| `/api/v1/attack-paths` | `GET, POST` | Yes | Viewer / Developer | BFS path synthesis & mitigation | **PASS** |
| `/api/v1/changes` | `GET, POST` | Yes | Viewer / Developer | IntentLock canonical hash | **PASS** |
| `/api/v1/changes/{id}` | `GET, PATCH` | Yes | Viewer / Developer | Auto-revokes approval on payload change | **PASS** |
| `/api/v1/changes/{id}/approve` | `POST` | Yes | Admin | Developer blocked (`403`) | **PASS** |
| `/api/v1/changes/{id}/execute` | `POST` | Yes | Admin | IntentLock + Org enforcementMode policy gate | **PASS** |
| `/api/v1/policies` | `GET, POST, PATCH` | Yes | Viewer / Admin | OPA / Cloud Guard / IntentLock / Agent rules | **PASS** |
| `/api/v1/policies/evaluate` | `POST` | Yes | Viewer | Evaluates target against active rules + `enforcementMode` | **PASS** |
| `/api/v1/cloud/resources` | `GET, POST` | Yes | Viewer (`read`) / Dev (`scan`) | CSPM resource compliance + Terraform plan drift evaluation | **PASS** (Vitest + Live `:3000` HTTP 200) |
| `/api/v1/ai-agents` | `GET, POST` | Yes | Viewer / Developer | Agent manifest & quotas | **PASS** |
| `/api/v1/ai-agents/{id}/execute` | `POST` | Yes | Developer | Tool allowlist + auto-quarantine on violation | **PASS** |
| `/api/v1/ai-agents/{id}/revoke` | `POST` | Yes | Admin | Kill-switch | **PASS** |
| `/api/v1/incidents` | `GET, POST` | Yes | Viewer / Developer | Incident log & creation | **PASS** |
| `/api/v1/incidents/{id}` | `PATCH` | Yes | Developer | Lifecycle transitions | **PASS** |
| `/api/v1/recovery/backups` | `GET, POST` | Yes | Viewer (`read`) / Admin (`write`) | SHA-256 snapshot creation & `verify_restore` SQLite integrity check | **PASS** (Vitest + Live `:3000` HTTP 200) |
| `/api/v1/deception` | `GET, POST` | Yes | Viewer / Developer | Canary tokens & tripwire alerts | **PASS** |
| `/api/v1/compliance` | `GET, PATCH` | Yes | Viewer / Developer | SOC2/ISO/HIPAA/GDPR controls | **PASS** |
| `/api/v1/compliance/export` | `GET` | Yes | Viewer | CSV / JSON compliance evidence bundle | **PASS** |
| `/api/v1/trust-center` | `GET, POST` | Yes | Viewer / Admin | Customer Trust Passport management | **PASS** |
| `/api/v1/trust-center/{id}` | `GET` | Public | None | Sanitized public posture; `410` on revocation | **PASS** |
| `/api/v1/trust-center/{id}/revoke` | `POST` | Yes | Admin | Immediate revocation | **PASS** |
| `/api/v1/connectors` | `GET` | Yes | Viewer | Masked AES-256-GCM vault status (`availabilityState`, `keyVersion`) | **PASS** (Live `:3000` HTTP 200) |
| `/api/v1/connectors/rotate-secrets` | `POST` | Yes | Admin | Re-encrypts connector envelopes under active vault key version | **PASS** (Vitest verified) |
| `/api/v1/connectors/{id}/configure` | `POST` | Yes | Admin | AES-256-GCM AAD vaulting + live PAT/Webhook test + AWS/Azure/GCP validation | **PASS** (Vitest verified) |
| `/api/v1/connectors/{id}/test` | `POST` | Yes | Admin | Live GitHub/OSV/AWS SigV4 STS/Azure/GCP/Slack/HTTP/OCI checks (`424` if unconfigured) | **PASS** (Vitest verified) |
| `/api/v1/connectors/{id}/disconnect` | `POST` | Yes | Admin | Clears credentials & sets `NOT_CONFIGURED` | **PASS** |
| `/api/v1/integrations/github/scan-repo` | `POST` | Yes | Developer | Live GitHub tree/manifest scan + SBOM + OSV | **PASS** (Vitest verified) |
| `/api/v1/integrations/osv/query` | `POST` | Yes | Developer | Live `https://api.osv.dev/v1/querybatch` CVE lookup | **PASS** (Vitest verified) |
| `/api/v1/integrations/http-probe` | `POST` | Yes | Developer | Safe redirect SSRF probe + `node:tls` X.509 certificate inspection | **PASS** (Vitest verified) |
| `/api/v1/integrations/oci/inspect` | `POST` | Yes | Developer (`scan`) | OCI Registry v2 manifest + digest verification | **PASS** |
| `/api/v1/webhooks/github` | `POST` | HMAC-SHA256 | Signature | `timingSafeEqual` + `webhook_deliveries` replay dedup | **PASS** (Vitest verified) |
| `/api/v1/webhooks/outbound/test` | `POST` | Yes | Admin | Strict HTTPS SSRF check + delivery logging | **PASS** (Vitest verified) |
| `/api/v1/team` | `GET, POST, PATCH` | Yes | Viewer / Admin | Role edits + `userStatus` (`Active`/`Disabled`) enforcement | **PASS** (Vitest verified) |
| `/api/v1/audit-logs` | `GET` | Yes | Viewer | SHA-256 hash-chained immutable ledger verification | **PASS** (Vitest verified) |
| `/api/v1/jobs` | `GET, POST` | Yes | Viewer (`read`) / Dev (`write`) | Enqueue, retry, exponential backoff & Dead Letter Queue (`Dead_Letter`) | **PASS** (Vitest + Live `:3000` HTTP 200) |
| `/api/v1/system/metrics` | `GET` | Yes | Viewer (`read`) | Live findings/remediation/jobs telemetry, `auditChain`, `vaultKeyVersion`, webhook history | **PASS** (Vitest + Live `:3000` HTTP 200) |
| `/api/v1/mcp` | `POST` | Yes | Viewer / Dev+ | JSON-RPC 2.0 MCP server (exact 5 tools) | **PASS** (Vitest verified) |
