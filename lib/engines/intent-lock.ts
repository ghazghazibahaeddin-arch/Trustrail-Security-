import { canonicalHash } from '@/lib/security/crypto';

export interface IntentLockPayload {
  targetAsset: string;
  previousStateHash: string;
  newStatePayload: unknown;
  purpose: string;
}

export interface IntentLockVerification {
  currentHash: string;
  isValid: boolean;
  status: 'Approved' | 'Modified_Revalidation_Required' | 'Locked' | 'Executed' | 'Rejected';
  reason: string;
}

export function computeChangeStateHash(payload: IntentLockPayload): string {
  return canonicalHash({
    targetAsset: payload.targetAsset,
    previousStateHash: payload.previousStateHash,
    newStatePayload: payload.newStatePayload,
    purpose: payload.purpose,
  });
}

export function verifyIntentLock(
  approvedHash: string | null | undefined,
  currentPayload: IntentLockPayload,
  currentStatus: string
): IntentLockVerification {
  const currentHash = computeChangeStateHash(currentPayload);

  if (currentStatus === 'Rejected') {
    return {
      currentHash,
      isValid: false,
      status: 'Rejected',
      reason: 'Change contract was explicitly rejected.',
    };
  }

  if (currentStatus === 'Executed') {
    return {
      currentHash,
      isValid: approvedHash === currentHash,
      status: 'Executed',
      reason: approvedHash === currentHash ? 'Executed state matches approved hash.' : 'Drift detected after execution!',
    };
  }

  if (!approvedHash) {
    return {
      currentHash,
      isValid: false,
      status: 'Locked',
      reason: 'Awaiting cryptographic approval bound to exact change hash.',
    };
  }

  if (approvedHash !== currentHash) {
    return {
      currentHash,
      isValid: false,
      status: 'Modified_Revalidation_Required',
      reason: 'Payload changed after approval! Previous IntentLock signature has been automatically invalidated.',
    };
  }

  return {
    currentHash,
    isValid: true,
    status: 'Approved',
    reason: 'IntentLock verified: payload digest exactly matches approved state.',
  };
}
