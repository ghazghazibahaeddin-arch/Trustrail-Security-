-- TRUSTRAIL SECURITY CLOUD — Production PostgreSQL Schema DDL (15+ Core & Hardened Tables)
-- Compatible with PostgreSQL 15+ / Cloud SQL / Aurora / Supabase

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  edition TEXT NOT NULL CHECK (edition IN ('developer', 'smb', 'enterprise')),
  tier_name TEXT NOT NULL,
  data_retention_days INTEGER NOT NULL DEFAULT 365,
  threat_sharing_opt_in BOOLEAN NOT NULL DEFAULT FALSE,
  enforcement_mode TEXT NOT NULL DEFAULT 'Enforce' CHECK (enforcement_mode IN ('Observe', 'Recommend', 'Enforce')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  mfa_secret_enc TEXT,
  mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
  email_verified BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memberships (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('Owner', 'Admin', 'Developer', 'Viewer')),
  title TEXT NOT NULL DEFAULT 'Engineer',
  status TEXT NOT NULL DEFAULT 'Active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
  last_scanned TIMESTAMPTZ NOT NULL,
  connected_aws_account TEXT,
  sbom_json JSONB,
  slsa_level TEXT NOT NULL DEFAULT 'None',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  owner TEXT NOT NULL,
  internet_exposed BOOLEAN NOT NULL DEFAULT FALSE,
  criticality TEXT NOT NULL CHECK (criticality IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  source_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  target_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  relation TEXT NOT NULL,
  evidence TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0.95,
  collected_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  triggered_by TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Queued', 'Running', 'Completed', 'Partial', 'Failed', 'Cancelled')),
  scanners_run JSONB NOT NULL,
  files_scanned INTEGER NOT NULL DEFAULT 0,
  findings_detected INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
  fingerprint TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  category TEXT NOT NULL,
  scanner TEXT NOT NULL,
  asset_name TEXT NOT NULL,
  file_path TEXT,
  line INTEGER,
  cve TEXT,
  cvss REAL NOT NULL,
  exploitability TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Open', 'In_Remediation', 'Under_Review', 'Resolved', 'False_Positive')),
  evidence TEXT NOT NULL,
  suggested_fix TEXT NOT NULL,
  resolution_evidence TEXT,
  assigned_owner TEXT NOT NULL,
  discovered_at TIMESTAMPTZ NOT NULL,
  verified_at TIMESTAMPTZ,
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
  new_state_payload JSONB NOT NULL,
  new_state_hash TEXT NOT NULL,
  approved_hash TEXT,
  purpose TEXT NOT NULL,
  risk_level TEXT NOT NULL CHECK (risk_level IN ('High', 'Medium', 'Low')),
  intent_lock_status TEXT NOT NULL,
  approved_by TEXT,
  evidence_summary TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  engine TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Enforced', 'Audit_Only', 'Disabled')),
  rule_code TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_agents (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  owner_team TEXT NOT NULL,
  permissions_json JSONB NOT NULL,
  allowlisted_tools_json JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Active', 'Quarantine', 'Revoked')),
  risk_level TEXT NOT NULL,
  actions_used INTEGER NOT NULL DEFAULT 0,
  action_limit INTEGER NOT NULL DEFAULT 25,
  last_action TEXT NOT NULL,
  canary_triggered BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('SEV-1', 'SEV-2', 'SEV-3')),
  status TEXT NOT NULL CHECK (status IN ('Open', 'Contained', 'Recovered', 'Closed')),
  affected_asset TEXT NOT NULL,
  owner TEXT NOT NULL,
  summary TEXT NOT NULL,
  playbook_name TEXT NOT NULL,
  actions_taken_json JSONB NOT NULL,
  opened_at TIMESTAMPTZ NOT NULL,
  closed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS canaries (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  location TEXT NOT NULL,
  token_hint TEXT NOT NULL,
  status TEXT NOT NULL,
  alerts_count INTEGER NOT NULL DEFAULT 0,
  last_triggered_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS compliance_controls (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  framework TEXT NOT NULL,
  code TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Verified', 'Needs_Evidence', 'Non_Compliant')),
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
  permissions_json JSONB NOT NULL,
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
  missing_permissions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
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
  role TEXT NOT NULL CHECK (role IN ('Owner', 'Admin', 'Developer', 'Viewer')),
  scopes_json JSONB NOT NULL DEFAULT '["read","scan","write"]'::jsonb,
  expires_at TIMESTAMPTZ,
  rotated_from_id TEXT,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS trust_receipts (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  scope_json JSONB NOT NULL,
  signature TEXT NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  access_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  org_id TEXT NOT NULL,
  actor_email TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  details TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS remediation_runs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('Patch_Generated', 'Tests_Passed', 'Rescan_Verified', 'Failed')),
  patch_diff TEXT NOT NULL,
  verification_command TEXT NOT NULL,
  verification_passed BOOLEAN NOT NULL DEFAULT FALSE,
  rescan_clean BOOLEAN NOT NULL DEFAULT FALSE,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  verified_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS recovery_backups (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_name TEXT NOT NULL,
  backup_type TEXT NOT NULL,
  checksum_sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  restore_tested_at TIMESTAMPTZ,
  restore_status TEXT NOT NULL CHECK (restore_status IN ('Untested', 'Verified', 'Failed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cloud_resources (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
  account_id TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_arn TEXT NOT NULL,
  region TEXT NOT NULL,
  exposure TEXT NOT NULL,
  compliant BOOLEAN NOT NULL DEFAULT TRUE,
  details_json JSONB NOT NULL,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  revoked_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS background_jobs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  job_type TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Queued', 'Running', 'Completed', 'Dead_Letter')),
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notification_deliveries (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  http_status INTEGER,
  summary TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connector_sync_runs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('initial', 'incremental', 'webhook', 'manual')),
  status TEXT NOT NULL CHECK (status IN ('Running', 'Completed', 'Partial', 'Failed')),
  assets_discovered INTEGER NOT NULL DEFAULT 0,
  events_imported INTEGER NOT NULL DEFAULT 0,
  failures_count INTEGER NOT NULL DEFAULT 0,
  cursor TEXT,
  error_message TEXT,
  started_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS internal_events (
  event_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  event_version TEXT NOT NULL DEFAULT '1.0',
  actor_id TEXT NOT NULL,
  source_connector TEXT NOT NULL,
  source_resource_id TEXT NOT NULL,
  affected_assets_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  correlation_id TEXT NOT NULL,
  causation_id TEXT,
  evidence_reference TEXT,
  payload_json JSONB NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  processing_status TEXT NOT NULL DEFAULT 'Pending' CHECK (processing_status IN ('Pending', 'Processing', 'Processed', 'Failed', 'Dead_Letter')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS vulnerability_intel (
  id TEXT PRIMARY KEY,
  cve_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('OSV', 'NVD', 'KEV', 'EPSS', 'GHSA')),
  source_url TEXT,
  kev_listed BOOLEAN NOT NULL DEFAULT FALSE,
  kev_due_date TEXT,
  epss_score REAL,
  epss_percentile REAL,
  cvss_score REAL,
  cwes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  fixed_versions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw_json JSONB,
  retrieved_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE(cve_id, source)
);

CREATE TABLE IF NOT EXISTS runners (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('scan', 'cicd', 'runtime_collector')),
  status TEXT NOT NULL CHECK (status IN ('Pending_Enrollment', 'Online', 'Degraded', 'Offline', 'Revoked')),
  token_hash TEXT NOT NULL UNIQUE,
  token_prefix TEXT NOT NULL,
  device_fingerprint TEXT,
  environment TEXT NOT NULL DEFAULT 'production',
  version TEXT NOT NULL DEFAULT '1.2.0',
  capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_heartbeat_at TIMESTAMPTZ,
  stats_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS runner_jobs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  runner_id TEXT REFERENCES runners(id) ON DELETE SET NULL,
  job_type TEXT NOT NULL,
  target_json JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Queued', 'Dispatched', 'Running', 'Completed', 'Failed', 'Cancelled')),
  timeout_sec INTEGER NOT NULL DEFAULT 300,
  result_json JSONB,
  signature TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS runtime_events (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  source TEXT NOT NULL CHECK (source IN ('otel', 'kubernetes_audit', 'falco', 'cloudtrail', 'custom')),
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  event_type TEXT NOT NULL,
  asset_id TEXT,
  actor TEXT NOT NULL,
  resource TEXT NOT NULL,
  summary TEXT NOT NULL,
  raw_json JSONB NOT NULL,
  correlated_finding_id TEXT,
  correlated_incident_id TEXT,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS siem_exports (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  destination TEXT NOT NULL CHECK (destination IN ('splunk', 'elastic', 'sentinel', 'webhook')),
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('Delivered', 'Queued', 'Failed')),
  http_status INTEGER,
  attempts INTEGER NOT NULL DEFAULT 1,
  error_message TEXT,
  exported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sso_configs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('oidc', 'saml', 'okta', 'entra')),
  issuer_url TEXT,
  client_id TEXT,
  metadata_xml_or_url TEXT,
  domain_hint TEXT,
  role_mapping_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scim_tokens (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(org_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_cloud_org ON cloud_resources(org_id, provider);
CREATE INDEX IF NOT EXISTS idx_events_org_status ON internal_events(org_id, processing_status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intel_cve ON vulnerability_intel(cve_id);
CREATE INDEX IF NOT EXISTS idx_runners_org ON runners(org_id, status);
CREATE INDEX IF NOT EXISTS idx_runtime_org ON runtime_events(org_id, received_at DESC);
