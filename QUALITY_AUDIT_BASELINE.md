# QUALITY_AUDIT_BASELINE.md

**Audit Timestamp:** 2026-11-19T03:11:00-08:00  
**Target Repository:** `/app/applet` (`ai-studio-applet@0.1.0`, Next.js 15.5.29 / React 19.2.1)  
**Scope:** Independent pre-modification baseline inspection of every file, build pipeline, typecheck, lint, API route, persistence layer, and UI module.

---

## 1. Initial Build, Typecheck & Lint State

| Check | Command | Outcome | Details |
| :--- | :--- | :--- | :--- |
| TypeScript Check | `npx tsc --noEmit` | **PASS** (exit 0) | No TypeScript compiler errors initially, though several fields rely on `any` or untyped payloads. |
| ESLint | `npm run lint` (`eslint .`) | **PASS** (exit 0) | Passed on initial state, though React `'use client'` placement errors were not caught by ESLint. |
| Production Build (default env) | `npm run build` | **FAIL** (exit 1) | Failed during static prerendering of `/500`: `Error: <Html> should not be imported outside of pages/_document`. Caused by `NODE_ENV=development` set in container environment without `NODE_ENV=production` override or custom App Router error boundary (`global-error.tsx`). |
| Production Build (`NODE_ENV=production`) | `NODE_ENV=production npm run build` | **PASS** (exit 0) | Built routes: `/` (Static, 26 kB), `/_not-found` (Static), `/api/gemini` (Dynamic). |
| Automated Test Suite | `unit / integration / e2e` | **NOT PRESENT** | Zero test files (`*.test.*`, `*.spec.*`), no test runner configured in `package.json`, no Playwright/Vitest setup. |

---

## 2. Existing Working Functionality (Verified in Source)

1. **Client-Side Tabbed Navigation Shell (`app/page.tsx`, `components/layout/Sidebar.tsx`)**:
   - Renders 24 sidebar views inside a single-page client state switcher (`activeTab` in `TrustrailProvider`).
   - Switches cleanly between the 24 module views.
2. **Client-Side Stateful Actions (`lib/use-trustrail.tsx`)**:
   - `VulnerabilitiesView`: Severity filter (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`), search input by title/asset, and `Mark Resolved` button updating client state.
   - `ChangeIntegrityView`: `Approve Change` and `Revoke IntentLock` toggle contract status in client memory.
   - `IncidentCommandView`: Form creates a new incident in client memory (`title`, `severity`).
   - `IntegrationsView`: `Connect`/`Disconnect` button toggles connector status in client memory.
   - `CliModal`: Interactive terminal UI accepting `help`, `clear`, `exit`, `trustrail scan`, `trustrail findings`, `trustrail graph`, `trustrail attest` using hardcoded client memory strings.
3. **Server-Side Gemini Route (`app/api/gemini/route.ts`)**:
   - Route exists at `/api/gemini` and calls `@google/genai` `ai.models.generateContent` server-side using `process.env.GEMINI_API_KEY`.

---

## 3. Existing Bugs, Incomplete Functionality & Architectural Gaps

### 3.1 Critical Defects Found
1. **Broken AI API Endpoint Path (`404 Not Found`)**:
   - `components/modules/AssistantModal.tsx:37` calls `fetch('/api/gemini/route', ...)` instead of `/api/gemini`.
   - `components/modules/RemediationCenterView.tsx:20` calls `fetch('/api/gemini/route', ...)` instead of `/api/gemini`.
   - Result: Both AI Assistant and AI Remediation Autopilot fail with 404 JSON parse errors in runtime.
2. **Invalid `'use client'` Directive Placement**:
   - `lib/use-trustrail.tsx:1` begins with `'v.tsx' // placeholder check or direct use client` before `'use client';`.
   - `components/modules/IntegrationsView.tsx:1` begins with `'v.tsx'` before `'use client';`.
   - `components/modules/BillingView.tsx:1` begins with `'v.tsx'` before `'use client';`.
   - In React Server Components / Next.js App Router, `'use client'` must be the very first statement or it is silently ignored if imported from a Server Component.
3. **Deprecated / Outdated `@google/genai` SDK & Model Usage**:
   - `package.json` uses `@google/genai: ^2.4.0` and `app/api/gemini/route.ts` uses `gemini-2.5-flash` without `httpOptions: { headers: { 'User-Agent': 'aistudio-build' } }` and without input validation or rate limiting.
4. **Default `npm run build` Failure**:
   - Fails when `NODE_ENV=development` is inherited from environment due to missing App Router error isolation (`app/error.tsx` / `app/global-error.tsx`) and `build` script lacking `NODE_ENV=production`.
5. **Non-Functional / Unwired Buttons & Controls Across Views**:
   - `Header.tsx`: Global search bar (`Search assets...`) updates local state only and filters nothing; notification dropdown items are non-interactive; no mobile drawer toggle for sidebar.
   - `Sidebar.tsx`: Hardcoded static badge numbers (`2 Critical`, `14`, `3`, `5`) that do not reflect actual state mutations; fixed `w-72` sidebar breaks mobile layout (`< 768px`) with no responsive collapse/drawer.
   - `OverviewDashboard.tsx`: Hardcoded text `"2 Critical require immediate patch"`, `"1 Contained & resolved"`, `"Score 98/100"` even when findings/incidents change.
   - `SecurityGraphView.tsx`: Initial `selectedNode` is `'payment-gateway-service'` which does not match any node ID (`repo-1`..`rds-prod`); `"Export Graph Evidence (JSON)"` button has no `onClick`; graph nodes are hardcoded instead of derived from projects/findings/agents.
   - `AttackPathsView.tsx`: `"Apply Fix"` button has no `onClick` handler.
   - `ProjectsView.tsx`: `"Repo Settings"` button has no `onClick` handler; no way to add/connect a new repository or run a real code/dependency/secret scan.
   - `SupplyChainView.tsx`: `"Export Enterprise SBOM"` and `"View SBOM"` buttons have no `onClick` handlers; SLSA/SBOM statuses are hardcoded `"Generated"` / `"Valid"` even for projects with `sbomGenerated: false` (`terraform-aws-core`, `legacy-customer-portal` — false claim!).
   - `SecurityPoliciesView.tsx`: `"Add Policy Rule"` button has no `onClick` handler; policies are static local arrays, never evaluated against findings/changes.
   - `AiAgentsView.tsx`: `"Revoke Authority"` button has no `onClick` handler; no tool execution testing or cumulative action limit enforcement.
   - `ComplianceView.tsx`: `"Export Evidence Pack (PDF)"` button has no `onClick` handler.
   - `TrustCenterView.tsx`: `"Generate Secure Share Link"` button has no `onClick` handler; no external share route, expiration, or revocation action.
   - `TeamAccessView.tsx`: `"Invite Team Member"` button has no `onClick` handler; static 3-member array.
   - `BillingView.tsx`: `"Upgrade Plan"` buttons have no `onClick` handler.
   - `SettingsView.tsx`: Inputs are uncontrolled `defaultValue` with no save handler; `"Download Audit Ledger (JSON)"` button has no `onClick` handler.
   - `IncidentCommandView.tsx`: `asset` state has no UI input field; no playbook execution, containment actions, status transitions, or post-incident report generation.
   - `CliModal.tsx`: `trustrail scan` simulates fake timeouts (`setTimeout`) instead of calling a real scan engine or updating findings.

### 3.2 Missing Backend, Persistence, Auth & Integration Layers
- **Database & Persistence**: No database exists. All mutations reset on page reload.
- **Authentication & RBAC**: No login/session/token auth, no role enforcement (`Owner`, `Admin`, `Developer`, `Viewer`), no CSRF/rate-limiting middleware.
- **Multi-Tenant Isolation**: Single hardcoded `initialOrganization` (`acme-cloud`). No second organization or tenant isolation check exists.
- **Real Backend APIs**: Only 1 route exists (`/api/gemini`). No REST endpoints for organizations, projects, scans, findings, attack paths, change contracts/IntentLock, policies, incidents, AI agents/MCP, compliance exports, trust center share links, or audit logs.
- **Real Scanner Engines**: No actual SAST, SCA, Secret Scanner (with redaction), IaC/Terraform plan evaluator, Container/SBOM generator, or Attack Path graph solver.
- **External Integrations**:
  - `IntegrationsView` displays 5 connectors (`GitHub Enterprise App`, `AWS Cross-Account IAM Role`, `Terraform Cloud`, `Docker Hub`, `Slack`) as `"Connected"` and `"Healthy"` **with zero credentials configured and zero real provider calls** — directly violating the truthfulness requirement!

### 3.3 Security & Design Concerns
- **Falsely Claimed Connected Status**: Connectors claim `"Connected"` / `"Healthy"` without credentials or API verification.
- **Falsely Claimed SBOM/Cosign Verification**: `SupplyChainView` shows `"Generated (CycloneDX)"` and `"Valid (sig_verified_ok)"` for all projects even when `sbomGenerated === false` and `slsaLevel === 'None'`.
- **No Secret Redaction Engine**: Initial mock finding `finding-101` literally prints `"super-secret-production-key-9982"` in plaintext evidence.
- **No Input Validation / Rate Limiting / Audit Ledger**: `/api/gemini` accepts arbitrary JSON without schema validation, auth, or prompt-injection boundary enforcement.
- **UI/UX Design Violations**: Static pill badges everywhere, decorative pulsing dots (`animate-pulse`), non-responsive fixed `w-72` sidebar on mobile, no light/dark mode toggle despite prompt requirement, no loading/empty/error states on data tables.

---

## 4. Missing Environment Configuration & External Blockers
- `GEMINI_API_KEY`: Server env var (presence checked dynamically at runtime).
- `GITHUB_TOKEN` / `GITHUB_APP_ID` / `GITHUB_PRIVATE_KEY` / `GITHUB_WEBHOOK_SECRET`: Not configured in `.env.example` or runtime environment.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_ROLE_ARN` / `AWS_EXTERNAL_ID`: Not configured.
- `SLACK_WEBHOOK_URL` / `SLACK_BOT_TOKEN`: Not configured.
- `DATABASE_URL` / `REDIS_URL`: Not configured (no external PostgreSQL/Redis daemon running in container; Node 22 built-in `node:sqlite` is available for durable local relational persistence with migrations and transactions).
