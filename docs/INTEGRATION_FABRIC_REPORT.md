# TRUSTRAIL Security Cloud — Master Integration Fabric Report

## 1. Architecture Overview

TRUSTRAIL Security Cloud connects all internal security engines, external providers, CI/CD runners, and runtime telemetry collectors through an interconnected **Integration Fabric**:

- **Standardized Connector Hub (19 Providers)**: Managed in SQLite (`connectors`, `connector_sync_runs`) and synchronized with `lib/db/postgres-schema.sql` (schema v5). Supports a 13-state lifecycle (`AVAILABLE`, `NOT_CONFIGURED`, `CONFIGURING`, `AUTHENTICATING`, `AUTHENTICATED`, `CONNECTED`, `INITIAL_SYNC`, `SYNCHRONIZING`, `HEALTHY`, `DEGRADED`, `ERROR`, `REAUTH_REQUIRED`, `DISCONNECTED`), sync cursors, asset/event counters, encrypted AES-256-GCM credential envelopes, and full purge via `DELETE /api/v1/connectors/[id]`.
- **Internal Event Bus & Transactional Outbox**: All core modules (`scans`, `github/scan-repo`, `remediation`, `cloud/resources`, `incidents`, `trust-center`, `webhooks/github`, `projects`, `events/ingest`, `runner`, `scim`) publish strongly typed `InternalEventEnvelope` messages into `internal_events` with SHA-256 `idempotency_key` deduplication, `correlation_id` lineage, cross-module subscriber automation, `Dead_Letter` escalation after 3 failed attempts, and replay via `POST /api/v1/fabric/events`.
- **Multi-Source Vulnerability Intelligence Hub**: Combines OSV.dev, NVD v2, CISA KEV catalog, and FIRST EPSS scores into `vulnerability_intel` (TTL-cached) and directly uplifts `lib/engines/risk-engine.ts` prioritization (`+15` for CISA KEV, `+6/+10` for EPSS).
- **Kubernetes & Container Security**: Deterministic Kubernetes YAML/JSON analyzer (`lib/integrations/kubernetes-analyzer.ts` -> `/api/v1/integrations/kubernetes/analyze`) flagging privileged containers, host namespaces/paths, cluster-admin/wildcard RBAC, and missing `NetworkPolicy` resources while populating graph nodes and findings.
- **TRUSTRAIL Runner & Runtime Telemetry Collector**: Token-authenticated (`Bearer tr_run_...`) remote agent lifecycle (`/api/v1/runner`, `/enroll`, `/heartbeat`, `/jobs`, `[id]`) plus runtime telemetry ingestion (`/api/v1/events/ingest`) supporting OpenTelemetry, Kubernetes Audit, Falco, and CloudTrail signals with automatic `SEV-1` incident correlation on critical anomalies.
- **SIEM Forwarders, Enterprise SSO & SCIM 2.0**: Outbound delivery & tracking (`/api/v1/siem/export`) for Splunk HEC, Elastic Security, Microsoft Sentinel, and webhooks; OIDC/SAML configuration (`/api/v1/sso`); and RFC 7644 SCIM 2.0 user provisioning (`/api/v1/scim/v2/Users`) with `Bearer tr_scim_...` authentication and RBAC group mapping.
- **Developer Surface**: Synchronized OpenAPI 3.1 spec (`/api/v1/openapi.json`), expanded 11-tool MCP server (`/api/v1/mcp`), CLI (`bin/trustrail.ts`), TypeScript SDK (`lib/sdk/trustrail-client.ts`), and zero-dependency Python 3 SDK (`sdk/python/trustrail_client.py`).

## 2. Fail-Closed External Credential Policy

- All external connectors requiring secret credentials (`github` private/App, `gitlab`, `bitbucket`, `aws`, `azure`, `gcp`, `slack`, `teams`, `email_alerts`, `siem_splunk`, `siem_elastic`) fail closed with **HTTP 424 `CREDENTIALS_REQUIRED`** or record `Queued` / `Skipped_Not_Configured` rather than fabricating passing external provider responses.
- Public / offline-capable engines (`terraform`, `osv`, `nvd_kev_epss`, `http_probe`, `oci` public images, `kubernetes` manifest analyzer, built-in `kms_vault`) execute real deterministic analysis or live unauthenticated API calls immediately.
