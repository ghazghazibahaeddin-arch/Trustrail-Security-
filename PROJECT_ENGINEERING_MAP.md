# TRUSTRAIL SECURITY CLOUD — PROJECT ENGINEERING MAP

## 1. Repository Architecture Overview

- **Runtime & Framework**: Next.js 15.4.9 (App Router), React 19.2.1, TypeScript 5.9.3 (`strict: true`), Tailwind CSS v4, `lucide-react` icons, `motion/react` animations.
- **Database Layer (Current)**: `node:sqlite` (`DatabaseSync`) with WAL mode, foreign keys enabled, schema migrations table (`schema_migrations`), deterministic multi-tenant seed data (`org-acme` + `org-northstar`).
- **Domain Engines (`/lib/engines/`)**:
  - `scanner-engine.ts`: Deterministic SAST, Secret Scanner (with mandatory secret redaction), SCA (`package.json`), CycloneDX 1.5 SBOM builder, Terraform HCL & Plan JSON analyzer, Dockerfile analyzer.
  - `policy-engine.ts`: OPA/Guard policy rule evaluator (`REQUIRE_COSIGN_SIGNATURE`, `BLOCK_PUBLIC_S3_ACL`, `BLOCK_OPEN_ADMIN_PORTS`, `INTENT_LOCK_APPROVAL`, `BLOCK_HIGH_CVSS`, `AGENT_LEAST_PRIVILEGE`).
  - `attack-path-engine.ts`: Deterministic BFS graph attack-path synthesizer linking open HIGH/CRITICAL findings across `assets` + `graph_edges` to crown jewels.
  - `intent-lock.ts`: Canonical JSON SHA-256 hash binding (`computeChangeStateHash` + `verifyIntentLock`) detecting post-approval tampering/drift.
  - `risk-engine.ts`: Context-weighted business risk scoring (`CVSS`, exploitability, internet exposure, asset criticality, active attack path membership, fix availability).
- **Security Layer (`/lib/security/`)**:
  - `auth.ts`: Dual Bearer API key (`tr_live_*`) + HMAC-signed cookie/Bearer session auth, `hasMinRole` RBAC hierarchy (`Viewer < Developer < Admin < Owner`).
  - `crypto.ts`: `scrypt` password hashing with `timingSafeEqual`, HMAC-SHA256 session tokens, GitHub HMAC webhook verification, canonical hashing, evidence secret redaction.
  - `connector-config.ts`: Secret masking helpers & connector config parsing.
  - `ssrf.ts`: SSRF guard validating protocol, credentials-in-URL, blocked local/internal hostnames, private/link-local/CGNAT/loopback/IPv6 IP ranges, and DNS resolution checks.
  - `rate-limit.ts`: Sliding-window in-memory rate limiter.
- **Integrations (`/lib/integrations/`)**:
  - `osv-client.ts`: Real HTTPS client for `https://api.osv.dev/v1/querybatch` & `/v1/vulns/{id}`.
- **API Routes (`/app/api/`)**:
  - Auth: `login`, `register`, `logout`, `session`, `switch-org`.
  - Core Platform: `organizations`, `projects`, `projects/[id]`, `scans`, `findings`, `findings/[id]`, `graph`, `attack-paths`, `changes`, `changes/[id]`, `changes/[id]/approve`, `changes/[id]/execute`, `policies`, `policies/evaluate`, `ai-agents`, `ai-agents/[id]/execute`, `ai-agents/[id]/revoke`, `incidents`, `incidents/[id]`, `deception`, `compliance`, `compliance/export`, `connectors`, `connectors/[id]/configure`, `connectors/[id]/test`, `connectors/[id]/disconnect`, `api-keys`, `api-keys/[id]`, `trust-center`, `trust-center/[id]`, `trust-center/[id]/revoke`, `team`, `audit-logs`, `openapi.json`.
  - External Integrations & AI: `integrations/github/scan-repo`, `integrations/osv/query`, `integrations/http-probe`, `webhooks/github`, `webhooks/outbound/test`, `gemini`, `health`.
  - MCP Server: `/api/v1/mcp` (JSON-RPC 2.0 `initialize`, `tools/list`, `tools/call`).
- **Developer Tooling (`/bin/`, `/lib/sdk/`)**:
  - `bin/trustrail.ts`: CLI supporting `scan`, `terraform-check`, `findings`, `graph`, `attest`.
  - `lib/sdk/trustrail-client.ts`: Typed TypeScript SDK client.
- **Frontend UI (`/app/`, `/components/`)**:
  - Public/Auth pages: `/login`, `/register`, `/trust/[id]`.
  - Authenticated Console (`/components/layout/` + `/components/modules/`): 24 navigation tabs covering Overview, Security Graph, Attack Paths, Projects, Vulnerabilities, Supply Chain, CI/CD, Cloud Security, Identity, API Security, AI Agents, Change Integrity, Policies, Remediation Center, Runtime Events, Incident Command, Recovery, Deception, Compliance, Trust Center, Integrations, Team Access, Billing, Settings + CLI Modal & AI Copilot Modal.
- **Automated Tests (`/tests/`)**:
  - 5 Vitest files totaling 26 tests (`engines.test.ts`, `api-and-security.test.ts`, `integrations-and-apikeys.test.ts`, `mcp-cli-sdk.test.ts`, `benchmark.test.ts`).
