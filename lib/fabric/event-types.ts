export type TrustrailEventType =
  | 'asset.discovered'
  | 'asset.updated'
  | 'repository.connected'
  | 'pull_request.opened'
  | 'pull_request.updated'
  | 'scan.started'
  | 'scan.completed'
  | 'scan.failed'
  | 'vulnerability.discovered'
  | 'secret.detected'
  | 'sbom.generated'
  | 'cloud.resource.discovered'
  | 'iam.permission_change_detected'
  | 'state.drift_detected'
  | 'attack_path.updated'
  | 'policy.evaluated'
  | 'remediation.proposed'
  | 'remediation.approved'
  | 'remediation.applied'
  | 'remediation.verified'
  | 'remediation.failed'
  | 'security_event.received'
  | 'anomaly.detected'
  | 'incident.created'
  | 'incident.updated'
  | 'incident.contained'
  | 'incident.resolved'
  | 'compliance.control_updated'
  | 'trust_receipt.created'
  | 'integration.connected'
  | 'integration.failed'
  | 'integration.reauth_required'
  | 'runner.enrolled'
  | 'runner.job_completed';

export type EventProcessingStatus = 'Pending' | 'Processing' | 'Processed' | 'Failed' | 'Dead_Letter';

export interface InternalEventEnvelope<T = Record<string, unknown>> {
  eventId: string;
  eventType: TrustrailEventType;
  eventVersion: string;
  tenantId: string;
  actorId: string;
  sourceConnector: string;
  sourceResourceId: string;
  affectedAssetIds: string[];
  correlationId: string;
  causationId?: string | null;
  timestamp: string;
  evidenceReference?: string | null;
  payload: T;
  idempotencyKey: string;
  processingStatus: EventProcessingStatus;
  attempts: number;
  lastError?: string | null;
  processedAt?: string | null;
}

export interface PublishEventInput<T = Record<string, unknown>> {
  orgId: string;
  eventType: TrustrailEventType;
  actorId: string;
  sourceConnector: string;
  sourceResourceId: string;
  affectedAssetIds?: string[];
  correlationId?: string;
  causationId?: string | null;
  evidenceReference?: string | null;
  payload: T;
  idempotencyKey?: string;
  simulateFailure?: boolean;
}
