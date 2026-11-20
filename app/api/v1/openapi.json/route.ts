import { NextResponse } from 'next/server';

export async function GET() {
  const spec = {
    openapi: '3.1.0',
    info: {
      title: 'Trustrail Security Cloud API',
      version: '1.0.0',
      description:
        'Multi-tenant cybersecurity control plane API covering posture discovery, SAST/Secret/SCA/SBOM/IaC/Container/CI scanning, attack path synthesis, IntentLock change integrity, OPA policy enforcement, AI Agent guardrails, Incident Command, Recovery Backups, and Trust Center attestations.',
    },
    servers: [{ url: '/' }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'HMAC-SHA256 Token' },
        sessionCookie: { type: 'apiKey', in: 'cookie', name: 'trustrail_session' },
      },
    },
    security: [{ bearerAuth: [] }, { sessionCookie: [] }],
    paths: {
      '/api/health': { get: { summary: 'System health and database readiness', security: [] } },
      '/api/gemini': { post: { summary: 'AI Security Copilot & remediation patch suggestion' } },
      '/api/v1/auth/session': { get: { summary: 'Inspect active authenticated session and memberships', security: [] } },
      '/api/v1/auth/login': {
        post: {
          summary: 'Authenticate user (with lockout & optional TOTP MFA) and issue session cookie + bearer token',
          security: [],
        },
      },
      '/api/v1/auth/register': {
        post: { summary: 'Create user account and isolated organization workspace', security: [] },
      },
      '/api/v1/auth/logout': {
        post: { summary: 'Terminate session cookie and revoke active JWT ID (jti)', security: [] },
      },
      '/api/v1/auth/refresh': { post: { summary: 'Rotate session JWT and revoke prior token jti' } },
      '/api/v1/auth/profile': {
        get: { summary: 'Get authenticated user profile and verification state' },
        patch: { summary: 'Update user name or change password with current password verification' },
      },
      '/api/v1/auth/verify-email': { post: { summary: 'Resend or verify email verification token' } },
      '/api/v1/auth/forgot-password': {
        post: { summary: 'Issue time-limited SHA-256 password reset token', security: [] },
      },
      '/api/v1/auth/reset-password': {
        post: { summary: 'Reset password using valid single-use reset token and clear lockouts', security: [] },
      },
      '/api/v1/auth/mfa/setup': {
        post: { summary: 'Generate encrypted RFC 6238 TOTP MFA secret and otpauth URI' },
      },
      '/api/v1/auth/mfa/verify': {
        post: { summary: 'Verify 6-digit TOTP code and enable MFA enforcement' },
        delete: { summary: 'Disable TOTP MFA for current user with password confirmation' },
      },
      '/api/v1/auth/switch-org': { post: { summary: 'Switch active multi-tenant organization context' } },
      '/api/v1/organizations': {
        get: { summary: 'Get active organization risk snapshot' },
        post: { summary: 'Create additional organization workspace' },
        patch: { summary: 'Update organization edition, retention, enforcement mode, and privacy settings (Admin+)' },
      },
      '/api/v1/projects': {
        get: { summary: 'List projects in active organization' },
        post: { summary: 'Create project and register repository asset (Developer+)' },
      },
      '/api/v1/projects/{id}': {
        get: { summary: 'Get project details' },
        patch: { summary: 'Update project metadata (Developer+)' },
        delete: { summary: 'Delete project (Admin+)' },
      },
      '/api/v1/projects/{id}/sbom': {
        get: { summary: 'Export and validate project SBOM in CycloneDX 1.5 or SPDX 2.3 format' },
        post: {
          summary: 'Verify SHA-256 / HMAC SLSA provenance attestation and upgrade project SLSA level (Developer+)',
        },
      },
      '/api/v1/scans': {
        get: { summary: 'List scan job executions' },
        post: { summary: 'Execute SAST/Secret/SCA/SBOM/IaC/Container/CI-Workflow scan (Developer+)' },
      },
      '/api/v1/findings': { get: { summary: 'Query prioritized findings with Risk Engine scoring' } },
      '/api/v1/findings/{id}': {
        get: { summary: 'Get finding details' },
        patch: { summary: 'Update finding status with verification evidence (Developer+)' },
      },
      '/api/v1/remediation': {
        get: { summary: 'List gated remediation verification runs' },
        post: { summary: 'Create remediation patch run for a finding (Developer+)' },
        patch: {
          summary: 'Progress remediation run through Tests_Passed -> Rescan_Verified closure gate (Developer+)',
        },
      },
      '/api/v1/graph': {
        get: { summary: 'Retrieve Unified Security Graph nodes, edges with provenance confidence, and attack paths' },
      },
      '/api/v1/attack-paths': {
        get: { summary: 'List synthesized multi-step attack paths' },
        post: { summary: 'Mitigate attack path by resolving contributing vulnerabilities (Developer+)' },
      },
      '/api/v1/changes': {
        get: { summary: 'List IntentLock change contracts' },
        post: { summary: 'Create IntentLock change contract (Developer+)' },
      },
      '/api/v1/changes/{id}': {
        get: { summary: 'Get IntentLock change contract and hash verification' },
        patch: { summary: 'Update change payload (triggers IntentLock revocation if already approved)' },
      },
      '/api/v1/changes/{id}/approve': { post: { summary: 'Approve, reject, or revoke IntentLock contract (Admin+)' } },
      '/api/v1/changes/{id}/execute': {
        post: { summary: 'Execute approved change after IntentLock and Policy enforcement mode verification' },
      },
      '/api/v1/policies': {
        get: { summary: 'List security policies' },
        post: { summary: 'Create security policy rule (Admin+)' },
        patch: { summary: 'Toggle policy enforcement mode (Admin+)' },
      },
      '/api/v1/policies/evaluate': {
        post: { summary: 'Evaluate target artifact or Terraform plan against policies honoring org enforcement mode' },
      },
      '/api/v1/ai-agents': {
        get: { summary: 'List registered AI agents and MCP servers' },
        post: { summary: 'Register AI agent with tool allowlist and quota (Developer+)' },
      },
      '/api/v1/ai-agents/{id}/execute': { post: { summary: 'Validate and execute allowlisted AI agent tool call' } },
      '/api/v1/ai-agents/{id}/revoke': {
        post: { summary: 'Revoke, quarantine, or restore AI agent credentials (Admin+)' },
      },
      '/api/v1/incidents': {
        get: { summary: 'List security incidents' },
        post: { summary: 'Open security incident and run response workflow (Developer+)' },
      },
      '/api/v1/incidents/{id}': {
        patch: { summary: 'Update incident status or append playbook action (Developer+)' },
      },
      '/api/v1/recovery/backups': {
        get: { summary: 'List SHA-256 checksummed recovery backup snapshots' },
        post: { summary: 'Create backup snapshot or execute restore integrity verification (Admin+)' },
      },
      '/api/v1/deception': {
        get: { summary: 'List active canary tokens and decoy traps' },
        post: { summary: 'Deploy canary or simulate tripwire trigger (Developer+)' },
      },
      '/api/v1/compliance': {
        get: { summary: 'List compliance framework controls' },
        patch: { summary: 'Update control status and evidence count (Developer+)' },
      },
      '/api/v1/compliance/export': { get: { summary: 'Download compliance evidence bundle (CSV or JSON)' } },
      '/api/v1/trust-center': {
        get: { summary: 'List issued Trust Center Passports' },
        post: { summary: 'Issue signed Trust Passport (Admin+)' },
      },
      '/api/v1/trust-center/{id}': { get: { summary: 'Public sanitized Trust Passport viewer endpoint', security: [] } },
      '/api/v1/trust-center/{id}/revoke': { post: { summary: 'Revoke or reinstate Trust Passport (Admin+)' } },
      '/api/v1/connectors': {
        get: { summary: 'List external connector status, availability state, encrypted vault version, and masked config' },
      },
      '/api/v1/connectors/{id}/configure': {
        post: { summary: 'Save AES-256-GCM encrypted per-org connector credentials or webhooks (Admin+)' },
      },
      '/api/v1/connectors/{id}/test': {
        post: { summary: 'Verify connector credentials via live AWS STS / GitHub / webhook / engine health checks (Admin+)' },
      },
      '/api/v1/connectors/{id}/disconnect': { post: { summary: 'Disconnect connector (Admin+)' } },
      '/api/v1/connectors/{id}': {
        delete: { summary: 'Disconnect and purge connector configuration & sync history (Admin+)' },
      },
      '/api/v1/connectors/{id}/sync': {
        get: { summary: 'List connector sync runs and cursor history' },
        post: { summary: 'Trigger initial or incremental connector synchronization (Developer+)' },
      },
      '/api/v1/connectors/rotate-secrets': {
        post: { summary: 'Rotate AES-256-GCM vault encryption key envelopes for org connectors (Admin+)' },
      },
      '/api/v1/fabric/events': {
        get: { summary: 'List Internal Event Bus transactional outbox events, statuses, and dependency map' },
        post: { summary: 'Publish an internal event or replay a Failed/Dead_Letter event (Developer+)' },
      },
      '/api/v1/intel/query': {
        get: { summary: 'List cached OSV/NVD/KEV/EPSS vulnerability intelligence records' },
        post: { summary: 'Query OSV.dev, NVD v2, CISA KEV, and FIRST EPSS and enrich finding risk scores (Developer+)' },
      },
      '/api/v1/integrations/kubernetes/analyze': {
        post: { summary: 'Analyze Kubernetes YAML manifests or cluster snapshot for RBAC/PodSecurity/NetworkPolicy risks (Developer+)' },
      },
      '/api/v1/events/ingest': {
        get: { summary: 'List ingested runtime telemetry events and correlated incidents' },
        post: { summary: 'Ingest OTel, Kubernetes Audit, Falco, or CloudTrail events (User Bearer or Runner Token)' },
      },
      '/api/v1/siem/export': {
        get: { summary: 'List SIEM export deliveries and status receipts' },
        post: { summary: 'Dispatch security event or posture alert to Splunk HEC, Elastic/Sentinel, or webhook (Developer+)' },
      },
      '/api/v1/runner': {
        get: { summary: 'List organization TRUSTRAIL Runners, job queue, and CI/CD pipeline snippets' },
        post: { summary: 'Issue runner enrollment token or queue a remote runner job (Admin+)' },
      },
      '/api/v1/runner/enroll': {
        post: { summary: 'Enroll TRUSTRAIL Runner with device fingerprint and capabilities (Runner Bearer tr_run_)' },
      },
      '/api/v1/runner/heartbeat': {
        post: { summary: 'Report TRUSTRAIL Runner health and metrics heartbeat (Runner Bearer tr_run_)' },
      },
      '/api/v1/runner/jobs': {
        get: { summary: 'Claim next queued job for the authenticated TRUSTRAIL Runner (Runner Bearer tr_run_)' },
        post: { summary: 'Submit signed TRUSTRAIL Runner job results and normalized findings (Runner Bearer tr_run_)' },
      },
      '/api/v1/runner/{id}': {
        delete: { summary: 'Revoke a TRUSTRAIL Runner immediately (Admin+)' },
      },
      '/api/v1/sso': {
        get: { summary: 'Get organization OIDC/SAML SSO configuration and SCIM 2.0 tokens' },
        post: { summary: 'Configure Enterprise SSO (OIDC/SAML/Okta/Entra) or issue/revoke SCIM 2.0 tokens (Admin+)' },
      },
      '/api/v1/scim/v2/Users': {
        get: { summary: 'RFC 7644 SCIM 2.0 list provisioned users (SCIM Bearer tr_scim_)' },
        post: { summary: 'RFC 7644 SCIM 2.0 create or update user & RBAC role mapping (SCIM Bearer tr_scim_)' },
      },
      '/api/v1/cloud/resources': {
        get: { summary: 'List discovered CSPM cloud resources and compliance state' },
        post: { summary: 'Evaluate cloud resource posture and ingest live AWS/Azure/GCP metadata (Developer+)' },
      },
      '/api/v1/api-keys': {
        get: { summary: 'List organization scoped API keys (Developer+)' },
        post: { summary: 'Issue scoped tr_live_ API key with scopes, expiry, and SHA-256 hash storage (Developer+)' },
      },
      '/api/v1/api-keys/{id}': { delete: { summary: 'Revoke scoped API key (Developer own / Admin+)' } },
      '/api/v1/api-keys/{id}/rotate': {
        post: { summary: 'Atomically rotate API key, revoking predecessor and preserving scopes (Developer own / Admin+)' },
      },
      '/api/v1/integrations/github/scan-repo': {
        post: { summary: 'Fetch & scan live GitHub repository tree, manifests, IaC & OSV advisories (Developer+)' },
      },
      '/api/v1/integrations/osv/query': {
        post: { summary: 'Query live OSV.dev CVE database against packages or project SBOM (Developer+)' },
      },
      '/api/v1/integrations/http-probe': {
        post: { summary: 'Execute SSRF-hardened live HTTP/TLS certificate & security header audit (Developer+)' },
      },
      '/api/v1/integrations/oci/inspect': {
        post: { summary: 'Inspect live OCI container registry manifests, digests, and Dockerfile security (Developer+)' },
      },
      '/api/v1/webhooks/github': {
        post: { summary: 'Receive GitHub HMAC-SHA256 signed webhook deliveries', security: [] },
      },
      '/api/v1/webhooks/outbound/test': {
        post: { summary: 'Dispatch live security posture digest to configured Slack/Discord/HTTPS webhook (Admin+)' },
      },
      '/api/v1/team': {
        get: { summary: 'List organization team members, roles, MFA status, and active state' },
        post: { summary: 'Invite team member with RBAC role (Admin+)' },
        patch: { summary: 'Update team member RBAC role or Active/Disabled status (Admin+)' },
      },
      '/api/v1/audit-logs': { get: { summary: 'Retrieve and verify SHA-256 hash-chained audit logs' } },
      '/api/v1/system/metrics': {
        get: { summary: 'Get tenant security metrics, audit chain verification, vault version, and webhook deliveries' },
      },
      '/api/v1/jobs': {
        get: { summary: 'List background worker jobs and Dead Letter queue entries' },
        post: { summary: 'Enqueue or retry background security job (Developer+)' },
      },
      '/api/v1/mcp': { post: { summary: 'JSON-RPC 2.0 Model Context Protocol (MCP) Server endpoint' } },
      '/api/v1/openapi.json': { get: { summary: 'OpenAPI 3.1 machine-readable specification', security: [] } },
    },
  };

  return NextResponse.json(spec);
}
