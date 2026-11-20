# TRUSTRAIL Security Cloud — Regression Test Report

**Test Runner:** Vitest `v5.1.1` (`npm test`)  
**Type Checker:** TypeScript `5.9.3` (`npm run typecheck`)  
**Linter:** ESLint `9.39.1` (`npm run lint`)  
**Production Build:** Next.js `15.4.9` (`npm run build`)

## 1. Automated Suite Summary
| Test Suite File | Scope Covered | Tests Run | Passed | Failed |
| :--- | :--- | :---: | :---: | :---: |
| `tests/unit/engines.test.ts` | SAST, Secret Redaction (AWS/GH/Stripe/Bearer/DB URI), SCA/CycloneDX 1.5 SBOM, Terraform HCL + Plan JSON, Dockerfile, Risk Engine, Attack Path BFS, OPA Policy Evaluator, IntentLock | 10 | **10** | 0 |
| `tests/integration/api-and-security.test.ts` | Health check, 401 Auth Guard, Viewer/Developer/Admin RBAC, Acme vs Northstar Multi-Tenant IDOR isolation, SQLi/malformed JSON, End-to-End Workflows 1–7, Webhook HMAC & replay, Audit Hash Chain | 9 | **9** | 0 |
| `tests/integration/mcp-cli-sdk.test.ts` | MCP JSON-RPC 2.0 (5 tools + Viewer 403 + Locked human gating), CLI (`scan`, `terraform-check`) on real fixtures, OpenAPI 3.1 route parity (40/40 routes) | 3 | **3** | 0 |
| `tests/performance/benchmark.test.ts` | 50x Scanner p95, 50x 100-node Attack Path BFS p95, 30x API SQLite/Risk/Graph p95 | 1 | **1** | 0 |
| **TOTAL** | **All Automated Unit, Integration, Security, CLI/MCP, and Performance Suites** | **23** | **23** | **0** |

## 2. Live HTTP & Runtime Verification (`http://127.0.0.1:3000`)
Executed via `npx tsx` against the live Next.js server immediately after `restart_dev_server`:
- `GET /api/health`: `200 OK` (`database.engine=sqlite`, `connected=true`, `geminiConfigured=true`)
- `GET /`: `200 OK` (`Trustrail` HTML rendered)
- `GET /trust/tr-9921`: `200 OK`
- `GET /api/v1/openapi.json`: `200 OK` (40 paths)
- `TrustrailClient` SDK Login + `listProjects` + `listFindings` + `getGraph` + `evaluatePolicy` + `verifyAuditChain`: **PASS** (`auditChainVerified: true`)
- Cookie Session Auth (`POST /api/v1/auth/login` -> `GET /api/v1/auth/session`): `200 OK` (`authenticated: true`)
- Cross-Tenant HTTP Isolation (`admin@northstar.io` -> `GET /api/v1/projects/proj-1`): `404 NOT_FOUND`
- `POST /api/v1/mcp` (`tools/list`): `200 OK` (`tools=5`)
- `POST /api/gemini`: `200 OK` (Live Gemini `gemini-4-hydrogen` output returned)

## 3. Build & Static Analysis Gates
- `npm run typecheck` (`tsc --noEmit`): **0 errors**
- `npm run lint` (`eslint .`): **0 errors, 0 warnings**
- `npm run build` (`NODE_ENV=production next build`): **Build succeeded cleanly**
