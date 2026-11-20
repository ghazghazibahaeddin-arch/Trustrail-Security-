# TRUSTRAIL SECURITY CLOUD — IMPLEMENTATION STATUS

Baseline audit executed prior to remediation (`tsc --noEmit` PASS, 26/26 Vitest PASS, `eslint .` PASS).

| Domain / Feature | Current Status | Notes |
|---|---|---|
| Multi-tenant Auth & RBAC | **Partial** | Login, register, logout, session, switch-org exist; missing password reset, email verification, brute-force lockout, TOTP MFA, session revocation, user profile update, user deactivation. |
| Connector Secret Encryption | **Defective / Incomplete** | Connector secrets (`githubToken`, `webhookUrl`, `awsExternalId`) stored in plaintext JSON inside `connectors.config_json` instead of authenticated `AES-256-GCM` encryption with key versioning. |
| Scoped API Keys | **Partial** | Hashing (`sha256`), prefix display, role capping & revocation work; missing explicit scopes, expiration (`expires_at`), key rotation, and auth failure rate limiting. |
| Unified Security Graph & Attack Paths | **Working (Needs Enrichment)** | Deterministic BFS attack paths & graph recalculation work; edges lack confidence scores and collection/verification timestamps. |
| Scanners (SAST/Secret/SCA/IaC/OCI) | **Partial** | JS/TS/Python/Dockerfile/HCL/Terraform Plan JSON & `package.json` work; missing lockfile parsing (`package-lock.json`, `requirements.txt`, `go.mod`, `pom.xml`), GitHub Actions workflow `.yml` analyzer, license risk checks, and OCI Registry v2 inspection. |
| SBOM & Supply Chain | **Partial** | CycloneDX 1.5 works; missing SPDX 2.3 export/validation, artifact SHA-256 digest & signature verification workflows. |
| Change Integrity & CI/CD Modes | **Partial** | IntentLock & OPA rules work; missing organization enforcement modes (`Observe`, `Recommend`, `Enforce`) and GitHub workflow CI security analysis. |
| Cloud Security (AWS/Azure/GCP) | **Partial** | Terraform & IAM node tracking exist; `aws` test returns `501 AWS_SDK_NOT_CONFIGURED`; missing real AWS SigV4 STS `GetCallerIdentity` verification & multi-cloud connector schema (`azure`, `gcp`) with explicit resource table. |
| AI Remediation Lifecycle | **Partial** | AI patch generation & finding resolution exist; missing structured remediation runs tracking patch -> test/rescan verification gate preventing unverified auto-resolution. |
| Attack Surface / HTTP / TLS Probe | **Partial** | SSRF guard + HTTP header checks work; missing multi-hop redirect re-validation, port allowlist, response byte cap, and `node:tls` X.509 certificate inspection (expiry, SAN, TLS version). |
| Incident, Runtime & Recovery | **Partial** | Incidents & deception work; Recovery view lacks persisted backup inventory and restore verification records; Runtime lacks structured observability metrics & notifications log. |
| Production DB & Ops Tooling | **Incomplete** | SQLite WAL only; missing PostgreSQL schema DDL, SQLite→PostgreSQL migration script, background job queue/DLQ, backup/restore verification, `Dockerfile`, and `DEPLOYMENT_GUIDE.md`. |
