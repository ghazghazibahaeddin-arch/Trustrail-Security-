# TRUSTRAIL SECURITY CLOUD — KNOWN DEFECTS

**Open Release-Blocking Defects:** **0**

All 11 audit defects (`DEF-01` through `DEF-11`) previously cataloged in the baseline audit have been resolved and verified (see `BUG_FIX_LOG.md` and `TEST_EVIDENCE_SUMMARY.md`):

| ID | Original Severity | Resolution Summary | Status |
|---|---|---|---|
| **DEF-01** | **CRITICAL** | Encrypted all connector secrets & MFA TOTP secrets via versioned `AES-256-GCM` AAD vault + `/api/v1/connectors/rotate-secrets`. | **RESOLVED** |
| **DEF-02** | **HIGH** | Implemented user `Active`/`Disabled` suspension, `revoked_tokens` JWT `jti` checks, 5-attempt brute-force lockout (`429`), TOTP MFA, email verification, and password reset. | **RESOLVED** |
| **DEF-03** | **HIGH** | Added `[80, 443]` port allowlisting, hop-by-hop safe redirects (`fetchWithSafeRedirects`), and `node:tls` X.509 certificate inspection. | **RESOLVED** |
| **DEF-04** | **HIGH** | Wrapped org provisioning in atomic SQLite transactions and introduced truthful `availabilityState` states (`AVAILABLE`, `NOT_CONFIGURED`, `CONNECTED`). | **RESOLVED** |
| **DEF-05** | **HIGH** | Added fine-grained API key scopes (`read`,`scan`,`write`,`admin`), TTL `expires_at`, key `/rotate`, and failed-key rate limiting. | **RESOLVED** |
| **DEF-06..11** | **MEDIUM/LOW** | Added polyglot lockfiles (`package-lock.json`, `requirements.txt`, `go.mod`, `pom.xml`), GitHub Actions YAML security rules, SPDX 2.3 + SLSA 2/3 attestation, org `enforcementMode`, AWS SigV4 STS, gated remediation verification, checksummed backup restore checks, background job DLQ, and full Settings/MFA UI controls. | **RESOLVED** |
