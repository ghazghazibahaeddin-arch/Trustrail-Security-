import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { hashPassword, sha256 } from '@/lib/security/crypto';
import { computeChangeStateHash } from '@/lib/engines/intent-lock';

let dbInstance: DatabaseSync | null = null;
let initializedPath: string | null = null;

function resolveDbPath(): string {
  return process.env.TRUSTRAIL_DB_PATH || path.join(process.cwd(), '.data', 'trustrail.db');
}

export function getDb(): DatabaseSync {
  const targetPath = resolveDbPath();
  if (dbInstance && initializedPath === targetPath) {
    return dbInstance;
  }

  if (targetPath !== ':memory:') {
    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(targetPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec('PRAGMA foreign_keys = ON;');

  runMigrations(db);
  seedInitialData(db);

  dbInstance = db;
  initializedPath = targetPath;
  return db;
}

export function withDbTransaction<T>(db: DatabaseSync, fn: () => T): T {
  db.exec('BEGIN IMMEDIATE;');
  try {
    const result = fn();
    db.exec('COMMIT;');
    return result;
  } catch (err) {
    try {
      db.exec('ROLLBACK;');
    } catch {
      // ignore rollback failure if already aborted
    }
    throw err;
  }
}

export function closeDbForTests(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
    initializedPath = null;
  }
}

function addColumnIfMissing(db: DatabaseSync, table: string, column: string, definition: string): void {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
  }
}

function runMigrations(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      edition TEXT NOT NULL CHECK(edition IN ('developer', 'smb', 'enterprise')),
      tier_name TEXT NOT NULL,
      data_retention_days INTEGER NOT NULL DEFAULT 365,
      threat_sharing_opt_in INTEGER NOT NULL DEFAULT 0,
      enforcement_mode TEXT NOT NULL DEFAULT 'Enforce' CHECK(enforcement_mode IN ('Observe', 'Recommend', 'Enforce')),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      mfa_enabled INTEGER NOT NULL DEFAULT 1,
      mfa_secret_enc TEXT,
      mfa_verified INTEGER NOT NULL DEFAULT 0,
      email_verified INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active', 'Disabled')),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS memberships (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK(role IN ('Owner', 'Admin', 'Developer', 'Viewer')),
      title TEXT NOT NULL DEFAULT 'Engineer',
      status TEXT NOT NULL DEFAULT 'Active',
      created_at TEXT NOT NULL,
      UNIQUE(user_id, org_id)
    );

    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      repo_url TEXT NOT NULL,
      branch TEXT NOT NULL DEFAULT 'main',
      language TEXT NOT NULL,
      framework TEXT NOT NULL,
      owner TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'protected',
      last_scanned TEXT NOT NULL,
      connected_aws_account TEXT,
      sbom_json TEXT,
      slsa_level TEXT NOT NULL DEFAULT 'None',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS assets (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
      name TEXT NOT NULL,
      asset_type TEXT NOT NULL,
      owner TEXT NOT NULL,
      internet_exposed INTEGER NOT NULL DEFAULT 0,
      criticality TEXT NOT NULL CHECK(criticality IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS graph_edges (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      source_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      target_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      relation TEXT NOT NULL,
      evidence TEXT NOT NULL,
      confidence REAL NOT NULL DEFAULT 0.95,
      collected_at TEXT,
      verified_at TEXT
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
      triggered_by TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Queued', 'Running', 'Completed', 'Partial', 'Failed', 'Cancelled')),
      scanners_run TEXT NOT NULL,
      files_scanned INTEGER NOT NULL DEFAULT 0,
      findings_detected INTEGER NOT NULL DEFAULT 0,
      error_message TEXT,
      started_at TEXT NOT NULL,
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
      asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
      fingerprint TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
      category TEXT NOT NULL,
      scanner TEXT NOT NULL,
      asset_name TEXT NOT NULL,
      file_path TEXT,
      line INTEGER,
      cve TEXT,
      cvss REAL NOT NULL,
      exploitability TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Open', 'In_Remediation', 'Under_Review', 'Resolved', 'False_Positive')),
      evidence TEXT NOT NULL,
      suggested_fix TEXT NOT NULL,
      resolution_evidence TEXT,
      assigned_owner TEXT NOT NULL,
      discovered_at TEXT NOT NULL,
      verified_at TEXT,
      UNIQUE(org_id, fingerprint)
    );

    CREATE TABLE IF NOT EXISTS change_contracts (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      actor TEXT NOT NULL,
      project TEXT NOT NULL,
      target_asset TEXT NOT NULL,
      previous_state_hash TEXT NOT NULL,
      new_state_payload TEXT NOT NULL,
      new_state_hash TEXT NOT NULL,
      approved_hash TEXT,
      purpose TEXT NOT NULL,
      risk_level TEXT NOT NULL CHECK(risk_level IN ('High', 'Medium', 'Low')),
      intent_lock_status TEXT NOT NULL,
      approved_by TEXT,
      evidence_summary TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      engine TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Enforced', 'Audit_Only', 'Disabled')),
      rule_code TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ai_agents (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      owner_team TEXT NOT NULL,
      permissions_json TEXT NOT NULL,
      allowlisted_tools_json TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Active', 'Quarantine', 'Revoked')),
      risk_level TEXT NOT NULL,
      actions_used INTEGER NOT NULL DEFAULT 0,
      action_limit INTEGER NOT NULL DEFAULT 25,
      last_action TEXT NOT NULL,
      canary_triggered INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('SEV-1', 'SEV-2', 'SEV-3')),
      status TEXT NOT NULL CHECK(status IN ('Open', 'Contained', 'Recovered', 'Closed')),
      affected_asset TEXT NOT NULL,
      owner TEXT NOT NULL,
      summary TEXT NOT NULL,
      playbook_name TEXT NOT NULL,
      actions_taken_json TEXT NOT NULL,
      opened_at TEXT NOT NULL,
      closed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS canaries (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      location TEXT NOT NULL,
      token_hint TEXT NOT NULL,
      status TEXT NOT NULL,
      alerts_count INTEGER NOT NULL DEFAULT 0,
      last_triggered_at TEXT
    );

    CREATE TABLE IF NOT EXISTS compliance_controls (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      framework TEXT NOT NULL,
      code TEXT NOT NULL,
      title TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Verified', 'Needs_Evidence', 'Non_Compliant')),
      evidence_count INTEGER NOT NULL DEFAULT 0,
      last_verified TEXT NOT NULL,
      owner TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS connectors (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      provider_key TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      auth_type TEXT NOT NULL,
      permissions_json TEXT NOT NULL,
      status TEXT NOT NULL,
      availability_state TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
      lifecycle_state TEXT NOT NULL DEFAULT 'NOT_CONFIGURED',
      health_check TEXT NOT NULL,
      last_sync TEXT NOT NULL,
      config_hint TEXT NOT NULL,
      config_json TEXT,
      sync_cursor TEXT,
      assets_discovered INTEGER NOT NULL DEFAULT 0,
      events_imported INTEGER NOT NULL DEFAULT 0,
      failure_count INTEGER NOT NULL DEFAULT 0,
      last_error TEXT,
      credential_expires_at TEXT,
      missing_permissions_json TEXT NOT NULL DEFAULT '[]',
      owner_email TEXT,
      data_direction TEXT NOT NULL DEFAULT 'bidirectional'
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL CHECK(role IN ('Owner', 'Admin', 'Developer', 'Viewer')),
      scopes_json TEXT NOT NULL DEFAULT '["read","scan","write"]',
      expires_at TEXT,
      rotated_from_id TEXT,
      last_used_at TEXT,
      created_at TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS trust_receipts (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      issued_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      scope_json TEXT NOT NULL,
      signature TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      access_count INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      org_id TEXT NOT NULL,
      actor_email TEXT NOT NULL,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      details TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS webhook_deliveries (
      delivery_id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      event_type TEXT NOT NULL,
      received_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS auth_verification_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      purpose TEXT NOT NULL CHECK(purpose IN ('email_verify', 'password_reset')),
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
      email_key TEXT PRIMARY KEY,
      attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      last_attempt_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS remediation_runs (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK(status IN ('Patch_Generated', 'Tests_Passed', 'Rescan_Verified', 'Failed')),
      patch_diff TEXT NOT NULL,
      verification_command TEXT NOT NULL,
      verification_passed INTEGER NOT NULL DEFAULT 0,
      rescan_clean INTEGER NOT NULL DEFAULT 0,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      verified_at TEXT
    );

    CREATE TABLE IF NOT EXISTS recovery_backups (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      target_name TEXT NOT NULL,
      backup_type TEXT NOT NULL,
      checksum_sha256 TEXT NOT NULL,
      size_bytes INTEGER NOT NULL DEFAULT 0,
      restore_tested_at TEXT,
      restore_status TEXT NOT NULL CHECK(restore_status IN ('Untested', 'Verified', 'Failed')),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS background_jobs (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      job_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Queued', 'Running', 'Completed', 'Dead_Letter')),
      attempts INTEGER NOT NULL DEFAULT 0,
      max_attempts INTEGER NOT NULL DEFAULT 3,
      last_error TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notification_deliveries (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      event_type TEXT NOT NULL,
      status TEXT NOT NULL,
      http_status INTEGER,
      summary TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cloud_resources (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      provider TEXT NOT NULL CHECK(provider IN ('aws', 'azure', 'gcp')),
      account_id TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_arn TEXT NOT NULL,
      region TEXT NOT NULL,
      exposure TEXT NOT NULL,
      compliant INTEGER NOT NULL DEFAULT 1,
      details_json TEXT NOT NULL,
      collected_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS connector_sync_runs (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
      mode TEXT NOT NULL CHECK(mode IN ('initial', 'incremental', 'webhook', 'manual')),
      status TEXT NOT NULL CHECK(status IN ('Running', 'Completed', 'Partial', 'Failed')),
      assets_discovered INTEGER NOT NULL DEFAULT 0,
      events_imported INTEGER NOT NULL DEFAULT 0,
      failures_count INTEGER NOT NULL DEFAULT 0,
      cursor TEXT,
      error_message TEXT,
      started_at TEXT NOT NULL,
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS internal_events (
      event_id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      event_version TEXT NOT NULL DEFAULT '1.0',
      actor_id TEXT NOT NULL,
      source_connector TEXT NOT NULL,
      source_resource_id TEXT NOT NULL,
      affected_assets_json TEXT NOT NULL DEFAULT '[]',
      correlation_id TEXT NOT NULL,
      causation_id TEXT,
      evidence_reference TEXT,
      payload_json TEXT NOT NULL,
      idempotency_key TEXT NOT NULL UNIQUE,
      processing_status TEXT NOT NULL DEFAULT 'Pending' CHECK(processing_status IN ('Pending', 'Processing', 'Processed', 'Failed', 'Dead_Letter')),
      attempts INTEGER NOT NULL DEFAULT 0,
      last_error TEXT,
      created_at TEXT NOT NULL,
      processed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS vulnerability_intel (
      id TEXT PRIMARY KEY,
      cve_id TEXT NOT NULL,
      source TEXT NOT NULL CHECK(source IN ('OSV', 'NVD', 'KEV', 'EPSS', 'GHSA')),
      source_url TEXT,
      kev_listed INTEGER NOT NULL DEFAULT 0,
      kev_due_date TEXT,
      epss_score REAL,
      epss_percentile REAL,
      cvss_score REAL,
      cwes_json TEXT NOT NULL DEFAULT '[]',
      fixed_versions_json TEXT NOT NULL DEFAULT '[]',
      raw_json TEXT,
      retrieved_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      UNIQUE(cve_id, source)
    );

    CREATE TABLE IF NOT EXISTS runners (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      mode TEXT NOT NULL CHECK(mode IN ('scan', 'cicd', 'runtime_collector')),
      status TEXT NOT NULL CHECK(status IN ('Pending_Enrollment', 'Online', 'Degraded', 'Offline', 'Revoked')),
      token_hash TEXT NOT NULL UNIQUE,
      token_prefix TEXT NOT NULL,
      device_fingerprint TEXT,
      environment TEXT NOT NULL DEFAULT 'production',
      version TEXT NOT NULL DEFAULT '1.2.0',
      capabilities_json TEXT NOT NULL DEFAULT '[]',
      last_heartbeat_at TEXT,
      stats_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS runner_jobs (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      runner_id TEXT REFERENCES runners(id) ON DELETE SET NULL,
      job_type TEXT NOT NULL,
      target_json TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Queued', 'Dispatched', 'Running', 'Completed', 'Failed', 'Cancelled')),
      timeout_sec INTEGER NOT NULL DEFAULT 300,
      result_json TEXT,
      signature TEXT,
      created_at TEXT NOT NULL,
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS runtime_events (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      source TEXT NOT NULL CHECK(source IN ('otel', 'kubernetes_audit', 'falco', 'cloudtrail', 'custom')),
      severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
      event_type TEXT NOT NULL,
      asset_id TEXT,
      actor TEXT NOT NULL,
      resource TEXT NOT NULL,
      summary TEXT NOT NULL,
      raw_json TEXT NOT NULL,
      correlated_finding_id TEXT,
      correlated_incident_id TEXT,
      received_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS siem_exports (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      destination TEXT NOT NULL CHECK(destination IN ('splunk', 'elastic', 'sentinel', 'webhook')),
      resource_type TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      correlation_id TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('Delivered', 'Queued', 'Failed')),
      http_status INTEGER,
      attempts INTEGER NOT NULL DEFAULT 1,
      error_message TEXT,
      exported_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sso_configs (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
      provider TEXT NOT NULL CHECK(provider IN ('oidc', 'saml', 'okta', 'entra')),
      issuer_url TEXT,
      client_id TEXT,
      metadata_xml_or_url TEXT,
      domain_hint TEXT,
      role_mapping_json TEXT NOT NULL DEFAULT '{}',
      enabled INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scim_tokens (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      token_prefix TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      revoked INTEGER NOT NULL DEFAULT 0,
      last_used_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id, severity, status);
    CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
    CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);
    CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id, id DESC);
    CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
    CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
    CREATE INDEX IF NOT EXISTS idx_remediation_org ON remediation_runs(org_id, finding_id);
    CREATE INDEX IF NOT EXISTS idx_jobs_org_status ON background_jobs(org_id, status);
    CREATE INDEX IF NOT EXISTS idx_cloud_org ON cloud_resources(org_id, provider);
    CREATE INDEX IF NOT EXISTS idx_events_org_status ON internal_events(org_id, processing_status, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_intel_cve ON vulnerability_intel(cve_id);
    CREATE INDEX IF NOT EXISTS idx_runners_org ON runners(org_id, status);
    CREATE INDEX IF NOT EXISTS idx_runtime_org ON runtime_events(org_id, received_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sync_runs_conn ON connector_sync_runs(connector_id, started_at DESC);
  `);

  addColumnIfMissing(db, 'organizations', 'enforcement_mode', `TEXT NOT NULL DEFAULT 'Enforce'`);
  addColumnIfMissing(db, 'users', 'mfa_secret_enc', 'TEXT');
  addColumnIfMissing(db, 'users', 'mfa_verified', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing(db, 'users', 'email_verified', 'INTEGER NOT NULL DEFAULT 1');
  addColumnIfMissing(db, 'users', 'status', `TEXT NOT NULL DEFAULT 'Active'`);
  addColumnIfMissing(db, 'graph_edges', 'confidence', 'REAL NOT NULL DEFAULT 0.95');
  addColumnIfMissing(db, 'graph_edges', 'collected_at', 'TEXT');
  addColumnIfMissing(db, 'graph_edges', 'verified_at', 'TEXT');
  addColumnIfMissing(db, 'connectors', 'config_json', 'TEXT');
  addColumnIfMissing(db, 'connectors', 'availability_state', `TEXT NOT NULL DEFAULT 'NOT_CONFIGURED'`);
  addColumnIfMissing(db, 'connectors', 'lifecycle_state', `TEXT NOT NULL DEFAULT 'NOT_CONFIGURED'`);
  addColumnIfMissing(db, 'connectors', 'sync_cursor', 'TEXT');
  addColumnIfMissing(db, 'connectors', 'assets_discovered', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing(db, 'connectors', 'events_imported', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing(db, 'connectors', 'failure_count', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing(db, 'connectors', 'last_error', 'TEXT');
  addColumnIfMissing(db, 'connectors', 'credential_expires_at', 'TEXT');
  addColumnIfMissing(db, 'connectors', 'missing_permissions_json', `TEXT NOT NULL DEFAULT '[]'`);
  addColumnIfMissing(db, 'connectors', 'owner_email', 'TEXT');
  addColumnIfMissing(db, 'connectors', 'data_direction', `TEXT NOT NULL DEFAULT 'bidirectional'`);
  addColumnIfMissing(db, 'api_keys', 'scopes_json', `TEXT NOT NULL DEFAULT '["read","scan","write"]'`);
  addColumnIfMissing(db, 'api_keys', 'expires_at', 'TEXT');
  addColumnIfMissing(db, 'api_keys', 'rotated_from_id', 'TEXT');

  for (const v of [1, 2, 3, 4, 5]) {
    const migrated = db.prepare('SELECT version FROM schema_migrations WHERE version = ?').get(v);
    if (!migrated) {
      db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(v, new Date().toISOString());
    }
  }
}

export function ensureBuiltInConnectors(db: DatabaseSync, orgId: string): void {
  const now = new Date().toISOString();
  const suffix = orgId === 'org-acme' ? '' : `${orgId.slice(-6)}-`;

  const hasGithub = Boolean(process.env.GITHUB_TOKEN);
  const hasAws = Boolean(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY);
  const hasSlack = Boolean(process.env.SLACK_WEBHOOK_URL);

  const builtIns = [
    {
      id: orgId === 'org-acme' ? 'conn-1' : `conn-${suffix}github`,
      key: 'github',
      name: 'GitHub App & Live Repo Scanner',
      cat: 'Source Control',
      auth: 'Per-Org Encrypted PAT / GITHUB_TOKEN + HMAC Webhooks',
      perms: ['repo:read', 'checks:write', 'pull_requests:write'],
      status: hasGithub ? 'Connected' : 'Disconnected',
      avail: hasGithub ? 'CONNECTED' : 'NOT_CONFIGURED',
      health: hasGithub ? 'Healthy' : 'Credentials_Required',
      hint: 'Save a GitHub PAT below for private repos, or scan any public GitHub repo immediately via the Live Repo Scanner.',
    },
    {
      id: orgId === 'org-acme' ? 'conn-2' : `conn-${suffix}aws`,
      key: 'aws',
      name: 'AWS Cross-Account IAM Role & STS',
      cat: 'Cloud',
      auth: 'AWS SigV4 STS GetCallerIdentity / AssumeRole',
      perms: ['sts:GetCallerIdentity', 'ReadOnlyAccess', 'CloudTrailReadOnly'],
      status: hasAws ? 'Connected' : 'Disconnected',
      avail: hasAws ? 'CONNECTED' : 'NOT_CONFIGURED',
      health: hasAws ? 'Healthy' : 'Credentials_Required',
      hint: 'Configure AWS IAM Role ARN & encrypted access credentials or set server AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.',
    },
    {
      id: orgId === 'org-acme' ? 'conn-3' : `conn-${suffix}terraform`,
      key: 'terraform',
      name: 'Terraform / OpenTofu Plan Engine',
      cat: 'Infrastructure',
      auth: 'Local / API Plan JSON Ingestion',
      perms: ['plan:read', 'policy:evaluate'],
      status: 'Connected',
      avail: 'AVAILABLE',
      health: 'Healthy',
      hint: 'Operational locally via Trustrail IaC Plan Parser & Policy Engine.',
    },
    {
      id: orgId === 'org-acme' ? 'conn-4' : `conn-${suffix}oci`,
      key: 'oci',
      name: 'Docker / OCI Registry & Dockerfile Scanner',
      cat: 'Artifact',
      auth: 'OCI Registry v2 Manifest API & Dockerfile Analysis',
      perms: ['sbom:generate', 'image:inspect'],
      status: 'Connected',
      avail: 'AVAILABLE',
      health: 'Healthy',
      hint: 'Operational for CycloneDX & SPDX SBOM generation, Dockerfile checks, and public OCI Registry digest inspection.',
    },
    {
      id: orgId === 'org-acme' ? 'conn-5' : `conn-${suffix}slack`,
      key: 'slack',
      name: 'Slack / Discord / Alert Webhook',
      cat: 'Notification',
      auth: 'Per-Org Encrypted Incoming Webhook URL',
      perms: ['chat:write', 'alerts:dispatch'],
      status: hasSlack ? 'Connected' : 'Disconnected',
      avail: hasSlack ? 'CONNECTED' : 'NOT_CONFIGURED',
      health: hasSlack ? 'Healthy' : 'Credentials_Required',
      hint: 'Save a Slack, Discord, or custom HTTPS webhook URL to dispatch live finding & incident alerts.',
    },
    {
      id: orgId === 'org-acme' ? 'conn-6' : `conn-${suffix}osv`,
      key: 'osv',
      name: 'OSV.dev Live CVE Intelligence Feed',
      cat: 'Threat Intel',
      auth: 'Public HTTPS API (api.osv.dev)',
      perms: ['advisories:query', 'sbom:enrich'],
      status: 'Connected',
      avail: 'AVAILABLE',
      health: 'Healthy',
      hint: 'Operational live against Google Open Source Vulnerabilities database (npm, PyPI, Go, Maven).',
    },
    {
      id: orgId === 'org-acme' ? 'conn-7' : `conn-${suffix}http_probe`,
      key: 'http_probe',
      name: 'Live HTTP/TLS & Security Header Probe',
      cat: 'API Security',
      auth: 'SSRF-Hardened Active TLS & Header Inspection',
      perms: ['headers:inspect', 'tls:verify'],
      status: 'Connected',
      avail: 'AVAILABLE',
      health: 'Healthy',
      hint: 'Operational live to audit HSTS, CSP, CORS, redirect hops, and X.509 TLS certificates.',
    },
    {
      id: orgId === 'org-acme' ? 'conn-8' : `conn-${suffix}azure`,
      key: 'azure',
      name: 'Microsoft Azure Entra & Subscription Posture',
      cat: 'Cloud',
      auth: 'Service Principal / Federated Identity',
      perms: ['Reader', 'SecurityReader'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Configure Azure Tenant ID & Subscription ID to track Azure cloud posture.',
    },
    {
      id: orgId === 'org-acme' ? 'conn-9' : `conn-${suffix}gcp`,
      key: 'gcp',
      name: 'Google Cloud Platform Security Command',
      cat: 'Cloud',
      auth: 'Workload Identity Federation / Service Account',
      perms: ['roles/viewer', 'roles/securitycenter.findingsViewer'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      lifecycle: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Configure GCP Project ID & workload federation to monitor GCP resources.',
      dir: 'inbound',
    },
    {
      id: orgId === 'org-acme' ? 'conn-10' : `conn-${suffix}gitlab`,
      key: 'gitlab',
      name: 'GitLab SaaS & Self-Managed Repositories',
      cat: 'Source Control',
      auth: 'Per-Org Encrypted Personal / Group Access Token',
      perms: ['read_api', 'read_repository', 'write_repository'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      lifecycle: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Save a GitLab Access Token and base URL (https://gitlab.com or self-managed) to scan repos & MRs.',
      dir: 'bidirectional',
    },
    {
      id: orgId === 'org-acme' ? 'conn-11' : `conn-${suffix}bitbucket`,
      key: 'bitbucket',
      name: 'Bitbucket Cloud & Pipelines',
      cat: 'Source Control',
      auth: 'Workspace App Password / OAuth Token',
      perms: ['repository:read', 'pullrequest:write'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      lifecycle: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Save Bitbucket workspace credentials to inspect repositories and pipeline builds.',
      dir: 'bidirectional',
    },
    {
      id: orgId === 'org-acme' ? 'conn-12' : `conn-${suffix}kubernetes`,
      key: 'kubernetes',
      name: 'Kubernetes Cluster & RBAC Posture Engine',
      cat: 'Kubernetes',
      auth: 'K8s Manifest / API Server Bearer Token + Cluster Collector',
      perms: ['pods:list', 'rbac:read', 'networkpolicies:read'],
      status: 'Connected',
      avail: 'AVAILABLE',
      lifecycle: 'HEALTHY',
      health: 'Healthy',
      hint: 'Operational for K8s manifest/snapshot RBAC, PodSecurity & NetworkPolicy inspection, or configure cluster endpoint.',
      dir: 'inbound',
    },
    {
      id: orgId === 'org-acme' ? 'conn-13' : `conn-${suffix}nvd_kev_epss`,
      key: 'nvd_kev_epss',
      name: 'NVD v2 + CISA KEV + FIRST EPSS Intel Hub',
      cat: 'Threat Intel',
      auth: 'Public Feeds (NVD API v2, CISA KEV JSON, FIRST EPSS)',
      perms: ['cve:enrich', 'kev:sync', 'epss:score'],
      status: 'Connected',
      avail: 'PUBLIC_FEED_READY',
      lifecycle: 'HEALTHY',
      health: 'Healthy',
      hint: 'Operational live for KEV catalog matching, EPSS exploitation probability scoring, and NVD CVE metadata.',
      dir: 'inbound',
    },
    {
      id: orgId === 'org-acme' ? 'conn-14' : `conn-${suffix}teams`,
      key: 'teams',
      name: 'Microsoft Teams Security Alerts',
      cat: 'Notification',
      auth: 'Per-Org Encrypted Incoming Webhook / Adaptive Card URL',
      perms: ['channel:post', 'incidents:notify'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      lifecycle: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Configure a Microsoft Teams Workflow/Incoming Webhook URL to route severity-filtered security alerts.',
      dir: 'outbound',
    },
    {
      id: orgId === 'org-acme' ? 'conn-15' : `conn-${suffix}email_alerts`,
      key: 'email_alerts',
      name: 'Security Email Delivery (Resend / Postmark / SES)',
      cat: 'Notification',
      auth: 'Encrypted Provider API Key + Verified Sender Address',
      perms: ['email:send', 'digest:dispatch'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      lifecycle: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Configure Resend, Postmark, or SES HTTP relay credentials to dispatch incident & digest emails.',
      dir: 'outbound',
    },
    {
      id: orgId === 'org-acme' ? 'conn-16' : `conn-${suffix}siem_splunk`,
      key: 'siem_splunk',
      name: 'Splunk HEC Security Event Exporter',
      cat: 'SIEM & Export',
      auth: 'Encrypted Splunk HTTP Event Collector Token',
      perms: ['hec:write', 'audit:stream'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      lifecycle: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Configure your Splunk HEC URL & token to stream correlated findings, incidents, and audit chains.',
      dir: 'outbound',
    },
    {
      id: orgId === 'org-acme' ? 'conn-17' : `conn-${suffix}siem_elastic`,
      key: 'siem_elastic',
      name: 'Elastic Security & Microsoft Sentinel Export',
      cat: 'SIEM & Export',
      auth: 'Encrypted Bulk Ingest API Key / Log Analytics Workspace Key',
      perms: ['events:export', 'incidents:export'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      lifecycle: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Configure Elastic Cloud endpoint/API key or Sentinel Workspace URL to forward Trustrail telemetry.',
      dir: 'outbound',
    },
    {
      id: orgId === 'org-acme' ? 'conn-18' : `conn-${suffix}sso_oidc`,
      key: 'sso_oidc',
      name: 'Enterprise SSO (OIDC / SAML 2.0 / SCIM 2.0)',
      cat: 'Identity & SSO',
      auth: 'OIDC Discovery / SAML Metadata + SCIM Bearer Token',
      perms: ['sso:authenticate', 'scim:provision', 'groups:map'],
      status: 'Disconnected',
      avail: 'NOT_CONFIGURED',
      lifecycle: 'NOT_CONFIGURED',
      health: 'Credentials_Required',
      hint: 'Configure Okta, Microsoft Entra ID, or generic OIDC/SAML issuer & SCIM role mapping.',
      dir: 'inbound',
    },
    {
      id: orgId === 'org-acme' ? 'conn-19' : `conn-${suffix}kms_vault`,
      key: 'kms_vault',
      name: 'HashiCorp Vault / AWS KMS Envelope Provider',
      cat: 'Secrets & KMS',
      auth: 'Vault AppRole / Token or AWS KMS Key ARN',
      perms: ['kms:encrypt', 'kms:decrypt', 'secrets:metadata'],
      status: 'Connected',
      avail: 'AVAILABLE',
      lifecycle: 'HEALTHY',
      health: 'Healthy',
      hint: 'Local AES-256-GCM AAD envelope vault active; optionally bind external HashiCorp Vault or AWS KMS key.',
      dir: 'bidirectional',
    },
  ];

  const existingKeys = new Set(
    (
      db
        .prepare('SELECT provider_key FROM connectors WHERE org_id = ?')
        .all(orgId) as Array<{ provider_key: string }>
    ).map((r) => r.provider_key)
  );

  for (const c of builtIns) {
    if (existingKeys.has(c.key)) continue;
    const lifecycleState =
      (c as { lifecycle?: string }).lifecycle ||
      (c.status === 'Connected' ? 'HEALTHY' : c.avail === 'AVAILABLE' ? 'AVAILABLE' : 'NOT_CONFIGURED');
    const dataDirection = (c as { dir?: string }).dir || 'bidirectional';
    db.prepare(
      `INSERT INTO connectors (id, org_id, provider_key, name, category, auth_type, permissions_json, status, availability_state, lifecycle_state, health_check, last_sync, config_hint, config_json, data_direction)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`
    ).run(
      c.id,
      orgId,
      c.key,
      c.name,
      c.cat,
      c.auth,
      JSON.stringify(c.perms),
      c.status,
      c.avail,
      lifecycleState,
      c.health,
      c.status === 'Connected' ? now : 'Never',
      c.hint,
      dataDirection
    );
  }
}

export function appendAuditLog(
  db: DatabaseSync,
  entry: {
    orgId: string;
    actorEmail: string;
    action: string;
    resourceType: string;
    resourceId: string;
    details: string;
  }
): void {
  const lastRow = db
    .prepare('SELECT entry_hash FROM audit_logs WHERE org_id = ? ORDER BY id DESC LIMIT 1')
    .get(entry.orgId) as { entry_hash: string } | undefined;
  const prevHash = lastRow?.entry_hash || 'GENESIS';
  const createdAt = new Date().toISOString();
  const entryHash = sha256(
    `${prevHash}|${entry.orgId}|${entry.actorEmail}|${entry.action}|${entry.resourceType}|${entry.resourceId}|${entry.details}|${createdAt}`
  );
  db.prepare(
    `INSERT INTO audit_logs (org_id, actor_email, action, resource_type, resource_id, details, prev_hash, entry_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    entry.orgId,
    entry.actorEmail,
    entry.action,
    entry.resourceType,
    entry.resourceId,
    entry.details,
    prevHash,
    entryHash,
    createdAt
  );
}

export function verifyAuditChain(
  db: DatabaseSync,
  orgId: string
): { valid: boolean; totalEntries: number; brokenAtId?: number } {
  const rows = db
    .prepare(
      `SELECT id, org_id, actor_email, action, resource_type, resource_id, details, prev_hash, entry_hash, created_at
       FROM audit_logs WHERE org_id = ? ORDER BY id ASC`
    )
    .all(orgId) as Array<{
    id: number;
    org_id: string;
    actor_email: string;
    action: string;
    resource_type: string;
    resource_id: string;
    details: string;
    prev_hash: string;
    entry_hash: string;
    created_at: string;
  }>;

  let expectedPrev = 'GENESIS';
  for (const row of rows) {
    if (row.prev_hash !== expectedPrev) {
      return { valid: false, totalEntries: rows.length, brokenAtId: row.id };
    }
    const recomputed = sha256(
      `${row.prev_hash}|${row.org_id}|${row.actor_email}|${row.action}|${row.resource_type}|${row.resource_id}|${row.details}|${row.created_at}`
    );
    if (recomputed !== row.entry_hash) {
      return { valid: false, totalEntries: rows.length, brokenAtId: row.id };
    }
    expectedPrev = row.entry_hash;
  }

  return { valid: true, totalEntries: rows.length };
}

function seedInitialData(db: DatabaseSync): void {
  const existingOrg = db.prepare('SELECT id FROM organizations LIMIT 1').get();
  if (existingOrg) return;

  const now = new Date().toISOString();

  // Tenant 1: Acme Cloud Technologies (Enterprise)
  db.prepare(
    `INSERT INTO organizations (id, name, slug, edition, tier_name, created_at)
     VALUES ('org-acme', 'Acme Cloud Technologies', 'acme-cloud', 'enterprise', 'Enterprise Security Grid', ?)`
  ).run(now);

  // Tenant 2: Northstar FinTech (SMB) - for real multi-tenant isolation & switching
  db.prepare(
    `INSERT INTO organizations (id, name, slug, edition, tier_name, created_at)
     VALUES ('org-northstar', 'Northstar FinTech', 'northstar-fintech', 'smb', 'Teams & SMB Edition', ?)`
  ).run(now);

  // Seed Users
  const demoPassHash = hashPassword('Trustrail!2026');
  const users = [
    { id: 'usr-sarah', email: 'sarah@acme.cloud', name: 'Sarah Connor' },
    { id: 'usr-alex', email: 'alex@acme.cloud', name: 'Alex Rivera' },
    { id: 'usr-viewer', email: 'auditor@acme.cloud', name: 'Jordan Blake (Auditor)' },
    { id: 'usr-northstar', email: 'admin@northstar.io', name: 'Maya Lin' },
  ];
  for (const u of users) {
    db.prepare(
      `INSERT INTO users (id, email, name, password_hash, mfa_enabled, created_at)
       VALUES (?, ?, ?, ?, 1, ?)`
    ).run(u.id, u.email, u.name, demoPassHash, now);
  }

  // Memberships
  const memberships = [
    { id: 'mem-1', userId: 'usr-sarah', orgId: 'org-acme', role: 'Owner', title: 'Chief Security Architect' },
    { id: 'mem-2', userId: 'usr-alex', orgId: 'org-acme', role: 'Developer', title: 'Senior Backend Engineer' },
    { id: 'mem-3', userId: 'usr-viewer', orgId: 'org-acme', role: 'Viewer', title: 'Compliance Auditor' },
    { id: 'mem-4', userId: 'usr-northstar', orgId: 'org-northstar', role: 'Owner', title: 'VP Engineering' },
  ];
  for (const m of memberships) {
    db.prepare(
      `INSERT INTO memberships (id, user_id, org_id, role, title, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'Active', ?)`
    ).run(m.id, m.userId, m.orgId, m.role, m.title, now);
  }

  // Projects for Acme
  const acmeProjects = [
    {
      id: 'proj-1',
      name: 'payment-gateway-service',
      repoUrl: 'github.com/acme/payment-gateway',
      branch: 'main',
      language: 'TypeScript',
      framework: 'Next.js / Node',
      owner: 'Sarah Connor',
      status: 'protected',
      lastScanned: '12 mins ago',
      aws: 'aws-prod-us-east-1 (92819283)',
      slsa: 'SLSA 2',
      sbom: JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        components: [
          { type: 'library', name: 'next', version: '15.4.9', purl: 'pkg:npm/next@15.4.9' },
          { type: 'library', name: 'zod', version: '4.6.7', purl: 'pkg:npm/zod@4.6.7' },
        ],
      }),
    },
    {
      id: 'proj-2',
      name: 'ai-agent-orchestrator',
      repoUrl: 'github.com/acme/ai-orchestrator',
      branch: 'main',
      language: 'Python',
      framework: 'FastAPI',
      owner: 'Alex Rivera',
      status: 'warning',
      lastScanned: '45 mins ago',
      aws: 'aws-ai-sandbox (19283746)',
      slsa: 'SLSA 1',
      sbom: JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        components: [
          { type: 'library', name: 'fastapi', version: '0.115.0', purl: 'pkg:pypi/fastapi@0.115.0' },
        ],
      }),
    },
    {
      id: 'proj-3',
      name: 'terraform-aws-core',
      repoUrl: 'github.com/acme/terraform-infra',
      branch: 'main',
      language: 'HCL',
      framework: 'Terraform',
      owner: 'DevOps Team',
      status: 'protected',
      lastScanned: '2 hours ago',
      aws: 'aws-prod-us-east-1 (92819283)',
      slsa: 'SLSA 2',
      sbom: null,
    },
    {
      id: 'proj-4',
      name: 'legacy-customer-portal',
      repoUrl: 'github.com/acme/customer-legacy',
      branch: 'master',
      language: 'JavaScript',
      framework: 'Express / React',
      owner: 'Legacy Support Team',
      status: 'critical',
      lastScanned: '5 hours ago',
      aws: 'aws-prod-us-east-1 (92819283)',
      slsa: 'None',
      sbom: null,
    },
  ];
  for (const p of acmeProjects) {
    db.prepare(
      `INSERT INTO projects (id, org_id, name, repo_url, branch, language, framework, owner, status, last_scanned, connected_aws_account, sbom_json, slsa_level, created_at)
       VALUES (?, 'org-acme', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(p.id, p.name, p.repoUrl, p.branch, p.language, p.framework, p.owner, p.status, p.lastScanned, p.aws, p.sbom, p.slsa, now);
  }

  // Project for Northstar (Tenant 2)
  db.prepare(
    `INSERT INTO projects (id, org_id, name, repo_url, branch, language, framework, owner, status, last_scanned, connected_aws_account, sbom_json, slsa_level, created_at)
     VALUES ('proj-ns-1', 'org-northstar', 'northstar-ledger-api', 'github.com/northstar/ledger-api', 'main', 'TypeScript', 'Node.js', 'Maya Lin', 'warning', '1 hour ago', NULL, NULL, 'None', ?)`
  ).run(now);

  // Unified Security Graph Assets for Acme
  const acmeAssets = [
    { id: 'asset-repo-2', proj: 'proj-2', name: 'github.com/acme/ai-orchestrator', type: 'Repository', owner: 'Alex Rivera', exposed: 0, crit: 'HIGH' },
    { id: 'asset-ci-1', proj: 'proj-2', name: 'deploy-prod.yml (GitHub Actions)', type: 'CI/CD Pipeline', owner: 'DevOps Team', exposed: 0, crit: 'HIGH' },
    { id: 'asset-iam-1', proj: 'proj-2', name: 'DataIngestLambdaRole', type: 'IAM Identity', owner: 'CloudSec Team', exposed: 0, crit: 'HIGH' },
    { id: 'asset-s3-1', proj: 'proj-4', name: 's3://acme-customer-backups-bucket', type: 'Cloud Storage', owner: 'DevOps Team', exposed: 1, crit: 'CRITICAL' },
    { id: 'asset-api-1', proj: 'proj-4', name: '/api/v1/internal/admin/exec', type: 'API Endpoint', owner: 'Legacy Support Team', exposed: 1, crit: 'HIGH' },
    { id: 'asset-rds-1', proj: 'proj-1', name: 'Prod PostgreSQL Cluster', type: 'Database', owner: 'Data Infra', exposed: 0, crit: 'CRITICAL' },
    { id: 'asset-repo-4', proj: 'proj-4', name: 'github.com/acme/customer-legacy', type: 'Repository', owner: 'Legacy Support Team', exposed: 1, crit: 'HIGH' },
  ];
  for (const a of acmeAssets) {
    db.prepare(
      `INSERT INTO assets (id, org_id, project_id, name, asset_type, owner, internet_exposed, criticality, created_at)
       VALUES (?, 'org-acme', ?, ?, ?, ?, ?, ?, ?)`
    ).run(a.id, a.proj, a.name, a.type, a.owner, a.exposed, a.crit, now);
  }

  // Graph Edges for Acme
  const acmeEdges = [
    { id: 'edge-1', src: 'asset-repo-2', dst: 'asset-ci-1', rel: 'TRIGGERS_PIPELINE', ev: '.github/workflows/deploy-prod.yml push trigger' },
    { id: 'edge-2', src: 'asset-ci-1', dst: 'asset-iam-1', rel: 'ASSUMES_ROLE', ev: 'OIDC federation role-to-assume arn:aws:iam::92819283:role/DataIngestLambdaRole' },
    { id: 'edge-3', src: 'asset-iam-1', dst: 'asset-rds-1', rel: 'READS_WRITES_DB', ev: 'IAM policy grants rds-db:connect and secretsmanager:GetSecretValue' },
    { id: 'edge-4', src: 'asset-repo-4', dst: 'asset-s3-1', rel: 'WRITES_BACKUPS_TO', ev: 'Backup cron exports config dumps to s3://acme-customer-backups-bucket' },
    { id: 'edge-5', src: 'asset-s3-1', dst: 'asset-api-1', rel: 'EXPOSES_TOKENS_TO', ev: 'Backup archive contains internal API service token' },
    { id: 'edge-6', src: 'asset-api-1', dst: 'asset-rds-1', rel: 'EXECUTES_ADMIN_QUERIES', ev: 'Admin endpoint connects directly to Prod PostgreSQL Cluster' },
  ];
  for (const e of acmeEdges) {
    db.prepare(
      `INSERT INTO graph_edges (id, org_id, source_asset_id, target_asset_id, relation, evidence)
       VALUES (?, 'org-acme', ?, ?, ?, ?)`
    ).run(e.id, e.src, e.dst, e.rel, e.ev);
  }

  // Seed Findings (with strictly redacted secret evidence!)
  const acmeFindings = [
    {
      id: 'finding-101',
      proj: 'proj-2',
      assetId: 'asset-repo-2',
      fp: 'seed-jwt-secret-101',
      title: 'Hardcoded JWT Secret in Auth Middleware',
      sev: 'CRITICAL',
      cat: 'SECRET',
      scanner: 'trustrail-secret-scanner',
      assetName: 'github.com/acme/ai-orchestrator',
      file: 'src/middleware/auth.py',
      line: 42,
      cve: null,
      cvss: 9.8,
      exp: 'High',
      status: 'Open',
      ev: 'Secret match: jwt_secret = "supe****9982" (Entropy: 4.8, full secret redacted)',
      fix: 'Move secret to AWS Secrets Manager and load via os.environ["JWT_SECRET"].',
      owner: 'Alex Rivera',
    },
    {
      id: 'finding-102',
      proj: 'proj-4',
      assetId: 'asset-s3-1',
      fp: 'seed-s3-public-102',
      title: 'AWS S3 Bucket Public Read-Write ACL Enabled',
      sev: 'CRITICAL',
      cat: 'CLOUD',
      scanner: 'trustrail-iac-terraform-scanner',
      assetName: 's3://acme-customer-backups-bucket',
      file: 'infra/s3_backups.tf',
      line: 14,
      cve: null,
      cvss: 9.1,
      exp: 'High',
      status: 'Open',
      ev: 'Bucket ACL grants AllUsers WRITE and READ_ACP permission.',
      fix: 'Apply Terraform block: block_public_acls = true and restrict bucket policy.',
      owner: 'DevOps Team',
    },
    {
      id: 'finding-103',
      proj: 'proj-4',
      assetId: 'asset-repo-4',
      fp: 'seed-lodash-103',
      title: 'Command Injection in lodash dependency < 4.17.21',
      sev: 'HIGH',
      cat: 'SCA',
      scanner: 'trustrail-sca-osv-adapter',
      assetName: 'github.com/acme/customer-legacy',
      file: 'package.json',
      line: 18,
      cve: 'CVE-2021-23337',
      cvss: 8.6,
      exp: 'Medium',
      status: 'In_Remediation',
      ev: 'Vulnerable package lodash@4.17.15 loaded in dependency tree.',
      fix: 'Upgrade lodash to ^4.17.21 via npm update lodash.',
      owner: 'Legacy Support Team',
    },
    {
      id: 'finding-104',
      proj: 'proj-2',
      assetId: 'asset-iam-1',
      fp: 'seed-iam-role-104',
      title: 'Over-privileged IAM Role for Lambda Worker',
      sev: 'HIGH',
      cat: 'CLOUD',
      scanner: 'trustrail-cloud-iam-analyzer',
      assetName: 'DataIngestLambdaRole',
      file: 'infra/iam.tf',
      line: 31,
      cve: null,
      cvss: 8.2,
      exp: 'Medium',
      status: 'Open',
      ev: 'Policy allows * actions on all s3:* and dynamodb:* resources.',
      fix: 'Narrow permissions to specific S3 bucket ARNs using least privilege.',
      owner: 'Sarah Connor',
    },
    {
      id: 'finding-105',
      proj: 'proj-4',
      assetId: 'asset-repo-4',
      fp: 'seed-sqli-105',
      title: 'SQL Injection in Legacy User Search Endpoint',
      sev: 'HIGH',
      cat: 'SAST',
      scanner: 'trustrail-sast-analyzer',
      assetName: 'github.com/acme/customer-legacy',
      file: 'server/controllers/userController.js',
      line: 88,
      cve: 'CVE-2023-4921',
      cvss: 8.5,
      exp: 'High',
      status: 'Open',
      ev: 'Unsanitized req.query.q concatenated directly into SQL query string.',
      fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE name = ?", [req.query.q])',
      owner: 'Legacy Support Team',
    },
  ];
  for (const f of acmeFindings) {
    db.prepare(
      `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
       VALUES (?, 'org-acme', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(f.id, f.proj, f.assetId, f.fp, f.title, f.sev, f.cat, f.scanner, f.assetName, f.file, f.line, f.cve, f.cvss, f.exp, f.status, f.ev, f.fix, f.owner, now);
  }

  // Northstar isolated finding (Tenant 2)
  db.prepare(
    `INSERT INTO assets (id, org_id, project_id, name, asset_type, owner, internet_exposed, criticality, created_at)
     VALUES ('asset-ns-1', 'org-northstar', 'proj-ns-1', 'github.com/northstar/ledger-api', 'Repository', 'Maya Lin', 1, 'CRITICAL', ?)`
  ).run(now);
  db.prepare(
    `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
     VALUES ('finding-ns-1', 'org-northstar', 'proj-ns-1', 'asset-ns-1', 'ns-fp-1', 'Northstar Confidential Ledger JWT Verification Bypass', 'CRITICAL', 'SAST', 'trustrail-sast-analyzer', 'github.com/northstar/ledger-api', 'src/auth.ts', 12, NULL, 9.5, 'High', 'Open', 'jwt.decode used instead of jwt.verify', 'Switch to jwt.verify with strict algorithm allowlist.', 'Maya Lin', ?)`
  ).run(now);

  // Change Contracts with genuine IntentLock canonical SHA-256 hashes
  const c1Payload = { ingress: [{ port: 22, cidr: '10.20.0.0/16' }] };
  const c1Prev = 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const c1Purpose = 'Restrict inbound SSH access (port 22) from 0.0.0.0/0 to corporate VPN CIDR only.';
  const c1Hash = computeChangeStateHash({
    targetAsset: 'sg-0892a9128374',
    previousStateHash: c1Prev,
    newStatePayload: c1Payload,
    purpose: c1Purpose,
  });

  db.prepare(
    `INSERT INTO change_contracts (id, org_id, title, actor, project, target_asset, previous_state_hash, new_state_payload, new_state_hash, approved_hash, purpose, risk_level, intent_lock_status, approved_by, evidence_summary, created_at)
     VALUES ('change-501', 'org-acme', 'Update AWS Production Security Group 22', 'Sarah Connor', 'terraform-aws-core', 'sg-0892a9128374', ?, ?, ?, NULL, ?, 'Medium', 'Locked', NULL, 'Terraform plan modifies 1 rule (- 0.0.0.0/0, + 10.20.0.0/16).', ?)`
  ).run(c1Prev, JSON.stringify(c1Payload), c1Hash, c1Purpose, now);

  const c2Payload = { package: 'lodash', version: '4.17.21' };
  const c2Prev = 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
  const c2Purpose = 'Upgrade lodash from 4.17.15 to 4.17.21 in package.json and lockfile.';
  const c2Hash = computeChangeStateHash({
    targetAsset: 'github.com/acme/payment-gateway',
    previousStateHash: c2Prev,
    newStatePayload: c2Payload,
    purpose: c2Purpose,
  });

  db.prepare(
    `INSERT INTO change_contracts (id, org_id, title, actor, project, target_asset, previous_state_hash, new_state_payload, new_state_hash, approved_hash, purpose, risk_level, intent_lock_status, approved_by, evidence_summary, created_at)
     VALUES ('change-502', 'org-acme', 'Deploy Hotfix for Lodash Vulnerability', 'Alex Rivera', 'payment-gateway-service', 'github.com/acme/payment-gateway', ?, ?, ?, ?, ?, 'Low', 'Approved', 'Sarah Connor', 'Unit tests verified. IntentLock signature bound.', ?)`
  ).run(c2Prev, JSON.stringify(c2Payload), c2Hash, c2Hash, c2Purpose, now);

  // Security Policies
  const policies = [
    { id: 'pol-1', name: 'Require Cosign Signature on Release Artifacts', engine: 'OPA Rego', sev: 'Critical', code: 'REQUIRE_COSIGN_SIGNATURE' },
    { id: 'pol-2', name: 'Block Public Read/Write ACLs on AWS S3 Buckets', engine: 'Cloud Guard', sev: 'Critical', code: 'BLOCK_PUBLIC_S3_ACL' },
    { id: 'pol-3', name: 'Block Open Admin Ports (22/3389) to 0.0.0.0/0', engine: 'Cloud Guard', sev: 'High', code: 'BLOCK_OPEN_ADMIN_PORTS' },
    { id: 'pol-4', name: 'Mandate IntentLock Cryptographic Approval on Changes', engine: 'IntentLock', sev: 'High', code: 'INTENT_LOCK_APPROVAL' },
    { id: 'pol-5', name: 'Block Dependencies with CVSS >= 9.0 in CI/CD', engine: 'SCA Guard', sev: 'Critical', code: 'BLOCK_HIGH_CVSS' },
    { id: 'pol-6', name: 'Enforce AI Agent Tool Allowlist & Cumulative Limits', engine: 'Agent Guard', sev: 'High', code: 'AGENT_LEAST_PRIVILEGE' },
  ];
  for (const pol of policies) {
    db.prepare(
      `INSERT INTO policies (id, org_id, name, engine, severity, status, rule_code, created_at)
       VALUES (?, 'org-acme', ?, ?, ?, 'Enforced', ?, ?)`
    ).run(pol.id, pol.name, pol.engine, pol.sev, pol.code, now);
  }

  // AI Agents
  const agents = [
    { id: 'agent-01', name: 'CustomerSupport-RAG-Bot', type: 'LLM Agent', team: 'Customer Success', perms: ['Read S3 KB', 'Create Support Ticket'], tools: ['search_kb', 'create_ticket'], status: 'Active', risk: 'Medium', used: 4, limit: 50, last: 'Answered ticket #9182', canary: 0 },
    { id: 'agent-02', name: 'CodeReview-Autonomous-Worker', type: 'Autonomous Worker', team: 'Engineering Core', perms: ['Read Git Repos', 'Propose PR Patch'], tools: ['git_read', 'run_tests', 'propose_patch'], status: 'Active', risk: 'High', used: 2, limit: 15, last: 'Prepared SCA patch draft', canary: 0 },
    { id: 'agent-03', name: 'External-MCP-DataCollector', type: 'MCP Server', team: 'Data Analytics', perms: ['Read Database Replicas'], tools: ['sql_read'], status: 'Quarantine', risk: 'High', used: 10, limit: 10, last: 'Attempted unauthorized schema export', canary: 1 },
  ];
  for (const ag of agents) {
    db.prepare(
      `INSERT INTO ai_agents (id, org_id, name, type, owner_team, permissions_json, allowlisted_tools_json, status, risk_level, actions_used, action_limit, last_action, canary_triggered, created_at)
       VALUES (?, 'org-acme', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(ag.id, ag.name, ag.type, ag.team, JSON.stringify(ag.perms), JSON.stringify(ag.tools), ag.status, ag.risk, ag.used, ag.limit, ag.last, ag.canary, now);
  }

  // Incidents
  db.prepare(
    `INSERT INTO incidents (id, org_id, title, severity, status, affected_asset, owner, summary, playbook_name, actions_taken_json, opened_at)
     VALUES ('inc-901', 'org-acme', 'Suspicious API Token Usage from External IP Range', 'SEV-2', 'Contained', 'AWS IAM Token (svc-deploy-key)', 'Security Operations Center', 'Detected 450 requests attempting to query sensitive API endpoints using an internal CI token.', 'Credential Compromise & Revocation', ?, ?)`
  ).run(
    JSON.stringify([
      'Revoked exposed CI deployment key.',
      'Rotated secret in CI/CD vault.',
      'Notified system owner.',
    ]),
    now
  );

  // Deception Canaries
  const canaries = [
    { id: 'can-1', type: 'Canary Token URL', loc: 'AWS S3 decoy object (canary-credentials.env)', hint: 'https://canary.trustrail.internal/t/c9a8...', status: 'Armed', alerts: 0 },
    { id: 'can-2', type: 'Honey API Key', loc: 'Repository decoy config file (.env.decoy)', hint: 'tr_decoy_****881a', status: 'Armed', alerts: 0 },
    { id: 'can-3', type: 'Decoy Database User', loc: 'PostgreSQL trap role (admin_backup_trap)', hint: 'role:admin_backup_trap', status: 'Triggered', alerts: 1 },
  ];
  for (const c of canaries) {
    db.prepare(
      `INSERT INTO canaries (id, org_id, type, location, token_hint, status, alerts_count)
       VALUES (?, 'org-acme', ?, ?, ?, ?, ?)`
    ).run(c.id, c.type, c.loc, c.hint, c.status, c.alerts);
  }

  // Compliance Controls
  const controls = [
    { id: 'ctrl-1', fw: 'OWASP Top 10:2025', code: 'A01:2025', title: 'Broken Access Control & Tenant Isolation', status: 'Verified', count: 12, owner: 'AppSec Team' },
    { id: 'ctrl-2', fw: 'OWASP Top 10:2025', code: 'A03:2025', title: 'Injection Flaw Mitigation', status: 'Needs_Evidence', count: 8, owner: 'Backend Team' },
    { id: 'ctrl-3', fw: 'SOC 2 Type II', code: 'CC6.1', title: 'Logical Access Security & IAM Least Privilege', status: 'Needs_Evidence', count: 14, owner: 'CloudSec Team' },
    { id: 'ctrl-4', fw: 'NIST SSDF', code: 'PW.1', title: 'Secure Coding Practices & SAST/SCA Checks', status: 'Verified', count: 18, owner: 'DevSecOps' },
    { id: 'ctrl-5', fw: 'SLSA v1.0', code: 'SLSA-2', title: 'Build Provenance & Tamper-Resistant SBOM', status: 'Needs_Evidence', count: 2, owner: 'DevSecOps' },
  ];
  for (const ctrl of controls) {
    db.prepare(
      `INSERT INTO compliance_controls (id, org_id, framework, code, title, status, evidence_count, last_verified, owner)
       VALUES (?, 'org-acme', ?, ?, ?, ?, ?, ?, ?)`
    ).run(ctrl.id, ctrl.fw, ctrl.code, ctrl.title, ctrl.status, ctrl.count, now.slice(0, 10), ctrl.owner);
  }

  // Truthful Connectors (including per-org configurability & always-ready OSV + HTTP probe)
  ensureBuiltInConnectors(db, 'org-acme');
  ensureBuiltInConnectors(db, 'org-northstar');

  // Trust Center Receipt
  db.prepare(
    `INSERT INTO trust_receipts (id, org_id, title, issued_at, expires_at, scope_json, signature, revoked, access_count)
     VALUES ('tr-9921', 'org-acme', 'Acme Security Passport & Q4 Evidence Summary', '2026-11-01', '2027-05-01', ?, ?, 0, 12)`
  ).run(
    JSON.stringify([
      'SOC 2 CC6.1 Evidence Tracking',
      'Automated SAST / SCA / Secret Scanning Enabled',
      'IntentLock Cryptographic Change Governance',
    ]),
    `sig_sha256_${sha256('tr-9921|org-acme|2026-11-01').slice(0, 24)}`
  );

  appendAuditLog(db, {
    orgId: 'org-acme',
    actorEmail: 'system@trustrail.cloud',
    action: 'DATABASE_SEEDED',
    resourceType: 'Organization',
    resourceId: 'org-acme',
    details: 'Initialized Trustrail unified security data model and cryptographic audit ledger.',
  });
}
