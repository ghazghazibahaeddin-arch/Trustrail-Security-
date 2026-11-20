# TRUSTRAIL Security Cloud — Frontend QA Report

**Framework:** Next.js 15.4.9 (App Router) + React 19.2.1 + Tailwind CSS v4  
**Verification Methods:** `eslint .` (`react-hooks`), `tsc --noEmit`, `NODE_ENV=production next build`, live HTTP SSR checks, and manual inspection of all 24 dashboard modules + public Trust Center + AuthGate.

## 1. Global Checks
- **Production Build (`NODE_ENV=production next build`):** **PASS** (Zero compilation or bundling errors).
- **ESLint (`eslint .`):** **PASS** (0 errors, 0 warnings — resolved 3 `react-hooks/set-state-in-effect` violations in `RemediationCenterView`, `SecurityGraphView`, `SettingsView`).
- **TypeScript (`tsc --noEmit`):** **PASS** (0 type errors).
- **SSR Entry Points:**
  - `GET /` -> HTTP `200` (`Trustrail Security Cloud` HTML rendered cleanly).
  - `GET /trust/tr-9921` -> HTTP `200` (Public Trust Passport viewer rendered cleanly).
- **Theme & Mobile Responsiveness:** Light/Dark toggle works via `html.dark` class; responsive mobile sidebar drawer (`Sidebar.tsx`) and responsive `sm:/md:/lg:` grids applied across views.

## 2. Module-by-Module UI Audit (26 Screens)
1. **AuthGate (`components/layout/AuthGate.tsx`)** — Sign-in, workspace registration, quick role demo credential autofill (`sarah@acme.cloud`, `alex@acme.cloud`, `auditor@acme.cloud`, `admin@northstar.io`). **PASS**
2. **Sidebar & Header (`Sidebar.tsx`, `Header.tsx`)** — Multi-org workspace switcher, live global search filtering, theme toggle, active user RBAC badge, sign out. **PASS**
3. **OverviewDashboard** — Real org risk score, rating, active attack paths, top priorities, quick actions. **PASS**
4. **SecurityGraphView** — Interactive SVG/node explorer hydrated from `/api/v1/graph`, JSON graph export, zero effect cascades. **PASS**
5. **AttackPathsView** — Real multi-step attack path visualizer + `"Sever & Verify Attack Path"` button -> `POST /api/v1/attack-paths`. **PASS**
6. **ProjectsView** — Create repository + on-demand custom/sample SAST/Secret/SCA/Terraform/Dockerfile scan launcher. **PASS**
7. **VulnerabilitiesView** — Live search/severity/status filters, Risk Engine explanation reasons, status update + resolution evidence. **PASS**
8. **SupplyChainView** — CycloneDX 1.5 SBOM viewer, real JSON SBOM download, SCA & supply-chain findings list. **PASS**
9. **RemediationCenterView** — Live AI patch generation via `/api/gemini` + verified closure workflow. **PASS**
10. **ChangeIntegrityView** — IntentLock create contract, simulate post-approval payload tampering (`Modified_Revalidation_Required`), Admin approve/revoke/execute. **PASS**
11. **SecurityPoliciesView** — Create policy, Admin enforcement mode selector, live Terraform HCL/Plan OPA evaluator. **PASS**
12. **AiAgentsView** — Register AI agent, test allowlisted vs disallowed tool calls, Admin quarantine/revoke/restore. **PASS**
13. **IncidentCommandView** — Open incident, update status (`Open`/`Contained`/`Recovered`/`Closed`), append playbook timeline actions. **PASS**
14. **DeceptionView** — Deploy decoy/canary tokens & simulate tripwire triggers with instant audit logging. **PASS**
15. **ComplianceView** — Framework filter, Admin/Dev control status dropdown, real CSV & JSON compliance bundle downloads (`/api/v1/compliance/export`). **PASS**
16. **TrustCenterView & `/trust/[id]`** — Issue signed Trust Passport, copy share URL, open public `/trust/[id]` page, Admin revoke/reinstate. **PASS**
17. **IntegrationsView** — Fixed stray `'v.tsx'` syntax error; truthful connector status (`Connected` vs `Disconnected / Credentials_Required`) + `Verify / Test` & `Disconnect`. **PASS**
18. **TeamAccessView** — Hydrated from `/api/v1/team` (removed hardcoded Acme list); invite member form + RBAC role switcher. **PASS**
19. **BillingView** — Fixed stray `'v.tsx'` syntax error; reads active `org.edition` dynamically + Admin plan switching. **PASS**
20. **SettingsView** — Controlled org governance form (`name`, `dataRetentionDays`, `threatSharingOptIn`), SHA-256 audit chain status badge, live audit log table & JSON download. **PASS**
21. **CicdSecurityView** — Derived from tenant projects/findings/policies + live `"Verify Pipeline Gate"` OPA evaluation. **PASS**
22. **CloudSecurityView** — Derived from tenant Security Graph cloud assets & AWS connector state (zero Acme leakage to Northstar). **PASS**
23. **IdentityAccessView** — Synthesized from tenant `teamMembers`, `aiAgents`, and IAM `graphNodes`. **PASS**
24. **ApiSecurityView** — Derived from tenant `API Endpoint` graph nodes & API/SAST findings + live OpenAPI 3.1 route count check. **PASS**
25. **RuntimeEventsView** — Streams live tenant triggered canaries, incidents, and audit ledger events. **PASS**
26. **RecoveryView** — Computes live readiness score from `auditChainVerified`, SBOM coverage, open incident count, and armed canaries. **PASS**
27. **AssistantModal & CliModal** — Grounded in live tenant risk summary, server-side Gemini chat, and real CLI/MCP configuration commands. **PASS**
