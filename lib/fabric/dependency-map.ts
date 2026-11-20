import type { TrustrailEventType } from '@/lib/fabric/event-types';

export interface IntegrationDependencySpec {
  providerKey: string;
  displayName: string;
  category:
    | 'Source Control'
    | 'CI/CD'
    | 'Cloud'
    | 'Infrastructure'
    | 'Container & Artifact'
    | 'Kubernetes'
    | 'Threat Intel'
    | 'API Security'
    | 'Runtime & Telemetry'
    | 'Identity & SSO'
    | 'Secrets & KMS'
    | 'Notification'
    | 'SIEM & Export';
  dataDirection: 'inbound' | 'outbound' | 'bidirectional';
  requiredCredentials: string[];
  emitsEvents: TrustrailEventType[];
  consumesEvents: TrustrailEventType[];
  connectedModules: string[];
  fallbackMode: string;
}

export const INTEGRATION_DEPENDENCY_MAP: IntegrationDependencySpec[] = [
  {
    providerKey: 'github',
    displayName: 'GitHub App & Live Repo Scanner',
    category: 'Source Control',
    dataDirection: 'bidirectional',
    requiredCredentials: ['GitHub App PEM + Installation ID or Encrypted PAT'],
    emitsEvents: [
      'repository.connected',
      'pull_request.opened',
      'pull_request.updated',
      'scan.completed',
      'vulnerability.discovered',
      'secret.detected',
      'sbom.generated',
    ],
    consumesEvents: ['remediation.proposed', 'policy.evaluated'],
    connectedModules: ['Security Graph', 'SAST/Secret/SCA Engines', 'SBOM Engine', 'Policy Gate', 'Remediation PRs'],
    fallbackMode: 'Public repository scanning works unauthenticated within GitHub API rate limits; private repos & PR checks require PAT/App.',
  },
  {
    providerKey: 'gitlab',
    displayName: 'GitLab SaaS & Self-Managed',
    category: 'Source Control',
    dataDirection: 'bidirectional',
    requiredCredentials: ['GitLab Personal/Group Access Token', 'Base URL'],
    emitsEvents: ['repository.connected', 'pull_request.opened', 'scan.completed', 'vulnerability.discovered'],
    consumesEvents: ['remediation.proposed', 'policy.evaluated'],
    connectedModules: ['Security Graph', 'SAST/SCA Engines', 'CI/CD Pipeline Guard'],
    fallbackMode: 'TRUSTRAIL Runner CI mode can scan repositories locally and push signed SARIF/findings.',
  },
  {
    providerKey: 'bitbucket',
    displayName: 'Bitbucket Cloud & Pipelines',
    category: 'Source Control',
    dataDirection: 'bidirectional',
    requiredCredentials: ['Bitbucket Workspace App Password / OAuth Token'],
    emitsEvents: ['repository.connected', 'scan.completed'],
    consumesEvents: ['remediation.proposed'],
    connectedModules: ['Security Graph', 'SCA/SAST Scanners'],
    fallbackMode: 'Local CLI & Runner CI mode supported without direct Bitbucket OAuth.',
  },
  {
    providerKey: 'aws',
    displayName: 'AWS Cross-Account IAM & STS',
    category: 'Cloud',
    dataDirection: 'inbound',
    requiredCredentials: ['IAM Role ARN + External ID + SigV4 Keys / STS'],
    emitsEvents: ['cloud.resource.discovered', 'iam.permission_change_detected', 'state.drift_detected'],
    consumesEvents: ['remediation.verified'],
    connectedModules: ['CSPM Evaluator', 'Attack Path Engine', 'Security Graph', 'Compliance CC6.1'],
    fallbackMode: 'Terraform IaC Plan & CSPM JSON snapshot evaluation works offline without live AWS keys.',
  },
  {
    providerKey: 'azure',
    displayName: 'Microsoft Azure Entra & ARM Posture',
    category: 'Cloud',
    dataDirection: 'inbound',
    requiredCredentials: ['Tenant ID', 'Subscription ID', 'AZURE_ACCESS_TOKEN'],
    emitsEvents: ['cloud.resource.discovered', 'state.drift_detected'],
    consumesEvents: [],
    connectedModules: ['CSPM Evaluator', 'Security Graph', 'Compliance Engine'],
    fallbackMode: 'Offline CSPM resource submission & Terraform Azurerm plan scanning remain active.',
  },
  {
    providerKey: 'gcp',
    displayName: 'Google Cloud Security Command',
    category: 'Cloud',
    dataDirection: 'inbound',
    requiredCredentials: ['GCP Project ID', 'GCP_ACCESS_TOKEN'],
    emitsEvents: ['cloud.resource.discovered', 'state.drift_detected'],
    consumesEvents: [],
    connectedModules: ['CSPM Evaluator', 'Security Graph', 'Compliance Engine'],
    fallbackMode: 'Offline GCP asset evaluation & Terraform Google provider HCL analysis remain active.',
  },
  {
    providerKey: 'kubernetes',
    displayName: 'Kubernetes Cluster & RBAC Posture Engine',
    category: 'Kubernetes',
    dataDirection: 'inbound',
    requiredCredentials: ['Kube API Endpoint + Read-Only Token (optional for live cluster; manifest mode always ready)'],
    emitsEvents: ['asset.discovered', 'vulnerability.discovered', 'state.drift_detected', 'security_event.received'],
    consumesEvents: ['policy.evaluated'],
    connectedModules: ['K8s RBAC/PodSecurity Analyzer', 'Security Graph', 'Attack Path Engine', 'Runtime Telemetry'],
    fallbackMode: 'YAML/JSON Kubernetes Deployment/ClusterRole/NetworkPolicy analysis runs locally immediately.',
  },
  {
    providerKey: 'terraform',
    displayName: 'Terraform / OpenTofu Plan Engine',
    category: 'Infrastructure',
    dataDirection: 'inbound',
    requiredCredentials: ['None (Built-in deterministic HCL & tfplan.json parser)'],
    emitsEvents: ['state.drift_detected', 'vulnerability.discovered', 'policy.evaluated'],
    consumesEvents: ['remediation.proposed'],
    connectedModules: ['IaC Scanner', 'IntentLock Change Protection', 'OPA Policy Engine'],
    fallbackMode: 'Always operational locally via API, CLI, and TRUSTRAIL Runner.',
  },
  {
    providerKey: 'oci',
    displayName: 'Container Registries (OCI / ECR / GHCR / Docker Hub)',
    category: 'Container & Artifact',
    dataDirection: 'inbound',
    requiredCredentials: ['Public registry supported directly; private registries via encrypted token'],
    emitsEvents: ['asset.discovered', 'sbom.generated', 'vulnerability.discovered'],
    consumesEvents: ['policy.evaluated'],
    connectedModules: ['Supply Chain SBOM & SLSA', 'Dockerfile Scanner', 'Cosign Signature Gate'],
    fallbackMode: 'Dockerfile & SBOM analysis continue locally even if remote registry is unreachable.',
  },
  {
    providerKey: 'osv',
    displayName: 'OSV.dev Live Advisory Feed',
    category: 'Threat Intel',
    dataDirection: 'inbound',
    requiredCredentials: ['None (Public api.osv.dev)'],
    emitsEvents: ['vulnerability.discovered'],
    consumesEvents: ['sbom.generated', 'scan.completed'],
    connectedModules: ['SCA Scanner', 'Risk Engine', 'SBOM Enricher'],
    fallbackMode: 'Falls back cleanly to local deterministic advisory signatures & cached vulnerability_intel table.',
  },
  {
    providerKey: 'nvd_kev_epss',
    displayName: 'NVD v2 + CISA KEV + FIRST EPSS Intel Hub',
    category: 'Threat Intel',
    dataDirection: 'inbound',
    requiredCredentials: ['None required (optional NVD_API_KEY for higher rate limits)'],
    emitsEvents: ['vulnerability.discovered', 'attack_path.updated'],
    consumesEvents: ['vulnerability.discovered', 'sbom.generated'],
    connectedModules: ['Risk Engine (KEV/EPSS Weighting)', 'Vulnerability Explorer', 'Incident Prioritization'],
    fallbackMode: 'Uses TTL-cached CVE/KEV/EPSS records in vulnerability_intel when external feeds are rate-limited.',
  },
  {
    providerKey: 'http_probe',
    displayName: 'HTTP / X.509 TLS Security Probe',
    category: 'API Security',
    dataDirection: 'inbound',
    requiredCredentials: ['None (SSRF-hardened active probe)'],
    emitsEvents: ['asset.discovered', 'vulnerability.discovered'],
    consumesEvents: [],
    connectedModules: ['API & Attack Surface Discovery', 'TLS Inspector', 'Security Graph'],
    fallbackMode: 'Strict DNS/IP SSRF guardrails reject private/loopback targets cleanly.',
  },
  {
    providerKey: 'slack',
    displayName: 'Slack / Discord / Outbound HTTPS Webhook',
    category: 'Notification',
    dataDirection: 'outbound',
    requiredCredentials: ['Encrypted HTTPS Incoming Webhook URL'],
    emitsEvents: ['integration.failed'],
    consumesEvents: ['incident.created', 'secret.detected', 'state.drift_detected', 'anomaly.detected', 'integration.failed'],
    connectedModules: ['Incident Command', 'Secret Alerts', 'Posture Digest'],
    fallbackMode: 'Undelivered alerts logged in notification_deliveries & queued for manual retry.',
  },
  {
    providerKey: 'teams',
    displayName: 'Microsoft Teams Alert Webhook',
    category: 'Notification',
    dataDirection: 'outbound',
    requiredCredentials: ['Encrypted Microsoft Teams Incoming Webhook URL'],
    consumesEvents: ['incident.created', 'secret.detected', 'state.drift_detected'],
    emitsEvents: [],
    connectedModules: ['Incident Command', 'Alert Routing'],
    fallbackMode: 'Logged cleanly in notification_deliveries if unconfigured.',
  },
  {
    providerKey: 'email_alerts',
    displayName: 'Security Alert Email (Resend / Postmark / SES)',
    category: 'Notification',
    dataDirection: 'outbound',
    requiredCredentials: ['Email Provider API Key', 'Verified From Address'],
    emitsEvents: [],
    consumesEvents: ['incident.created', 'incident.contained', 'remediation.failed'],
    connectedModules: ['Incident Command', 'Compliance Notifications'],
    fallbackMode: 'Records queued status in notification_deliveries when SMTP/HTTP provider key is missing.',
  },
  {
    providerKey: 'siem_splunk',
    displayName: 'Splunk HEC Exporter',
    category: 'SIEM & Export',
    dataDirection: 'outbound',
    requiredCredentials: ['Splunk HEC URL', 'HEC Bearer Token'],
    emitsEvents: [],
    consumesEvents: ['security_event.received', 'incident.created', 'vulnerability.discovered', 'trust_receipt.created'],
    connectedModules: ['Event Bus', 'Audit Ledger', 'Runtime Telemetry'],
    fallbackMode: 'Records Queued/Failed export receipts in siem_exports with correlation_id for replay.',
  },
  {
    providerKey: 'siem_elastic',
    displayName: 'Elastic Security & Microsoft Sentinel Exporter',
    category: 'SIEM & Export',
    dataDirection: 'outbound',
    requiredCredentials: ['Elastic/Sentinel Endpoint URL', 'API Key / Shared Key'],
    emitsEvents: [],
    consumesEvents: ['security_event.received', 'incident.created', 'anomaly.detected'],
    connectedModules: ['Event Bus', 'Runtime Telemetry', 'Incident Command'],
    fallbackMode: 'Supports on-demand JSON/CEF/NDJSON export bundle download and replay.',
  },
  {
    providerKey: 'sso_oidc',
    displayName: 'Enterprise SSO (OIDC / SAML 2.0 / SCIM 2.0)',
    category: 'Identity & SSO',
    dataDirection: 'inbound',
    requiredCredentials: ['IdP Issuer / SAML Metadata URL', 'Client ID', 'SCIM Bearer Token'],
    emitsEvents: ['iam.permission_change_detected'],
    consumesEvents: [],
    connectedModules: ['Auth & Session', 'RBAC Role Mapping', 'Team & Access'],
    fallbackMode: 'Built-in email/scrypt + TOTP MFA + API key authentication remains primary.',
  },
  {
    providerKey: 'kms_vault',
    displayName: 'HashiCorp Vault / AWS KMS Envelope Provider',
    category: 'Secrets & KMS',
    dataDirection: 'bidirectional',
    requiredCredentials: ['Built-in AES-256-GCM active; optional Vault Address/Token or AWS KMS Key ARN'],
    emitsEvents: ['integration.reauth_required'],
    consumesEvents: ['integration.connected'],
    connectedModules: ['Connector Vault', 'Secret Rotation', 'Audit Ledger'],
    fallbackMode: 'Local HKDF/AES-256-GCM AAD envelope vault always active.',
  },
];
