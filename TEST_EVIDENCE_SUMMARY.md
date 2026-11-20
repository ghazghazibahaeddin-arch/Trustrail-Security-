# TRUSTRAIL Security Cloud — Test Evidence Summary

**Execution Date:** 2026-11-20  
**Suite Status:** **8/8 Test Files Passed — 39/39 Tests Passed (100% Pass Rate)**

## 1. Automated Verification Gates Executed
| Gate | Command | Result |
| :--- | :--- | :--- |
| TypeScript Compiler | `npm run typecheck` (`tsc --noEmit`) | **PASS (0 errors)** |
| ESLint Static Analysis | `npm run lint` (`eslint .`) | **PASS (0 errors, 0 warnings)** |
| Vitest Automated Suite | `npm test` (`vitest run`) | **PASS (8 files, 39/39 tests)** |
| Next.js Production Build | `npm run build` (`NODE_ENV=production next build`) | **PASS** |
| Live Runtime Smoke Test | Live HTTP requests against `http://127.0.0.1:3000` | **PASS** |

## 2. Vitest Breakdown by Test File
| Test File | Scope Covered | Tests | Status |
| :--- | :--- | :---: | :--- |
| `tests/unit/engines.test.ts` | SAST, secret redaction, SCA/CycloneDX, Terraform Plan & HCL, Dockerfile, Graph BFS, Risk scoring, IntentLock, Policy Engine | 10 | **PASS** |
| `tests/unit/security-hardening.test.ts` | AES-256-GCM AAD vault & key rotation, RFC 6238 TOTP MFA, SSRF port/IP blocking, Observe/Recommend/Enforce policy modes, SPDX 2.3 conversion/validation, SLSA 2/3 attestation, polyglot npm lockfile/PyPI/Go/Maven + GitHub Actions scanner | 6 | **PASS** |
| `tests/integration/api-and-security.test.ts` | Health DB check, 401 unauthenticated denials, RBAC 403 enforcement, IDOR 404/403 multi-tenant isolation, SQLi safety, IntentLock tamper gate, GitHub webhook HMAC/replay, Attack-Path remediation clearing | 9 | **PASS** |
| `tests/integration/integrations-and-apikeys.test.ts` | New user atomic org provisioning, masked connector secrets, live `api.osv.dev` CVE lookup, live HTTP probe + SSRF block, live GitHub repo scan, outbound webhook, API key auth | 3 | **PASS** |
| `tests/integration/mcp-cli-sdk.test.ts` | MCP JSON-RPC 2.0 (5 tools, RBAC, human-gated IntentLock remediation), CLI `scan` & `terraform-check`, TypeScript SDK, 100% OpenAPI route parity | 3 | **PASS** |
| `tests/integration/auth-mfa-lockout.test.ts` | Email verification + replay block, 5-attempt brute-force lockout (`429`) + password reset unlock, TOTP MFA login enforcement, JWT `refresh` & `logout` `jti` revocation, Admin account disabling (`403`/`401`), API key scope (`403 INSUFFICIENT_SCOPE`) & rotation | 4 | **PASS** |
| `tests/integration/vault-scanners-sbom-recovery.test.ts` | Raw SQLite ciphertext inspection (0 plaintext secrets) & vault key rotation, polyglot manifest/GHA scan + SPDX/SLSA 3 API, gated remediation (`409 VERIFICATION_GATE_BLOCKED` -> `run_verification` -> `rescan_and_resolve`), checksummed backup restore verification, background job DLQ & retry, CSPM evaluation, `verifyAuditChain` | 3 | **PASS** |
| `tests/performance/benchmark.test.ts` | Latency p95 benchmarks: `scan_p95=0.42ms`, `graph_100nodes_p95=0.26ms`, `api_findings_graph_p95=4.60ms` | 1 | **PASS** |

## 3. Live Server Verification (`http://127.0.0.1:3000`)
- `GET /api/health` -> `200` (`{"status":"ok","db":true,"schemaVersion":4}`)
- `GET /api/v1/openapi.json` -> `200` (**63 documented paths**, 100% route parity)
- `POST /api/v1/auth/login` -> `200` (`Owner` session token issued)
- `GET /api/v1/system/metrics`, `/connectors`, `/cloud/resources`, `/remediation`, `/recovery/backups`, `/jobs` -> all `200`
- `POST /api/v1/auth/logout` -> `200`, followed immediately by `GET /api/v1/system/metrics` using same Bearer token -> `401` (JWT `jti` revocation verified live)
