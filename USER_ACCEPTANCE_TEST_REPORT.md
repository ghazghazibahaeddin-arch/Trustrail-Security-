# TRUSTRAIL Security Cloud — User Acceptance Test (UAT) Report

**Test Approach:** Simulated realistic journeys for all 4 customer/operator personas across API, CLI, MCP, and UI workflows.

## Persona 1: Independent Developer (`founder@newstartup.dev` — Developer Edition)
- **Scenario:** Self-register new isolated workspace -> scan repository containing SQLi, AWS key, vulnerable `minimist@1.2.5`, and public S3 Terraform config -> verify findings & CycloneDX SBOM -> run CLI offline scan -> mitigate finding.
- **Outcome:** **PASS** — Verified in `tests/integration/api-and-security.test.ts` (`RegisterRoute`, `ScansRoute`, `AttackPathsRoute`) and `tests/integration/mcp-cli-sdk.test.ts` (`bin/trustrail.ts scan`). Raw secrets were redacted in all stored/printed outputs.

## Persona 2: Startup Engineering Team Lead / Developer (`alex@acme.cloud` — Developer Role)
- **Scenario:** Scan updated code -> inspect prioritized P0/P1 findings and attack paths -> attempt restricted Admin actions (`approve` change contract, create OPA policy, issue Trust Passport) -> verify system blocks privilege escalation.
- **Outcome:** **PASS** — Developer can execute scans and resolve findings cleanly while Admin-only approvals (`POST /api/v1/changes/[id]/approve`), policies (`POST /api/v1/policies`), and Trust Passports (`POST /api/v1/trust-center`) return HTTP `403`.

## Persona 3: Enterprise CISO / Security Architect (`sarah@acme.cloud` — Owner Role)
- **Scenario:** Review attack paths -> create & approve IntentLock change contract -> test tampering protection -> execute approved change -> register AI Agent & block rogue tool invocation -> deploy & trigger canary -> issue & revoke Trust Passport -> verify SHA-256 audit ledger & export SOC 2 CSV compliance evidence.
- **Outcome:** **PASS** — All 7 end-to-end workflows verified in `tests/integration/api-and-security.test.ts` and live `:3000` endpoints. Tampering after approval automatically invalidated IntentLock (`Modified_Revalidation_Required`) and blocked execution (`409`).

## Persona 4: External Auditor & Cross-Tenant Operator (`auditor@acme.cloud` Viewer & `admin@northstar.io` Tenant 2)
- **Scenario:** Viewer reviews compliance controls, exports CSV evidence pack, and verifies audit log chain while prevented from mutating findings/scans; Tenant 2 (`Northstar Bio`) operates in complete isolation with zero visibility into `Acme Cloud Technologies`.
- **Outcome:** **PASS** — Viewer receives `403` on mutations (both REST & MCP); Northstar receives `404` on Acme resource IDs and `403` on `/auth/switch-org` both in Vitest and live HTTP `:3000`. Public customer viewer works without login on `/trust/[id]` and immediately returns `410` upon revocation.
