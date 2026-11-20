interface RateLimitBucket {
  count: number;
  resetAt: number;
}

const g = globalThis as typeof globalThis & { __trustrailRateBuckets?: Map<string, RateLimitBucket> };
const buckets = g.__trustrailRateBuckets ?? (g.__trustrailRateBuckets = new Map<string, RateLimitBucket>());

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export function checkRateLimit(
  key: string,
  maxRequests = 60,
  windowMs = 60_000
): RateLimitResult {
  const now = Date.now();
  const existing = buckets.get(key);

  if (!existing || existing.resetAt <= now) {
    const next: RateLimitBucket = { count: 1, resetAt: now + windowMs };
    buckets.set(key, next);
    return { allowed: true, remaining: maxRequests - 1, resetAt: next.resetAt };
  }

  if (existing.count >= maxRequests) {
    return { allowed: false, remaining: 0, resetAt: existing.resetAt };
  }

  existing.count += 1;
  return {
    allowed: true,
    remaining: Math.max(0, maxRequests - existing.count),
    resetAt: existing.resetAt,
  };
}

export function resetRateLimitBuckets(): void {
  buckets.clear();
}
