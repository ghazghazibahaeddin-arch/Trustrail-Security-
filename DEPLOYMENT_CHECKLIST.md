# TRUSTRAIL Security Cloud — Deployment Checklist

## 1. Environment Variables
Configure in your deployment secret manager (never commit `.env` files; see `.env.example`):
- [ ] `GEMINI_API_KEY` — Server-only Gemini API key for `/api/gemini` AI Copilot & Remediation Autopilot.
- [ ] `TRUSTRAIL_SESSION_SECRET` — Minimum 32-byte random hex string for signing session cookies & Bearer tokens across restarts/replicas.
- [ ] `APP_URL` — Public HTTPS origin URL for Share Links & Trust Center references.
- [ ] `TRUSTRAIL_DB_PATH` (optional) — Persistent volume path for SQLite database (defaults to `.data/trustrail.db`).
- [ ] `GITHUB_WEBHOOK_SECRET` (optional) — HMAC-SHA256 secret matching GitHub repository/App webhook settings.
- [ ] `GITHUB_TOKEN` (optional) — Read-only token for GitHub connector health checks.
- [ ] `SLACK_WEBHOOK_URL` (optional) — Incoming webhook URL for Slack alerting verification.

## 2. Pre-Deployment Verification Steps
1. Install production dependencies: `npm ci`
2. Run typecheck, lint, and full automated test suite:
   ```bash
   npm run typecheck
   npm run lint
   npm test
   ```
3. Build production Next.js bundle:
   ```bash
   npm run build
   ```
4. Ensure persistent writable volume is mounted at `/app/.data` (or `TRUSTRAIL_DB_PATH` parent directory).
5. Start server on port 3000:
   ```bash
   npm start
   ```

## 3. Post-Deployment Smoke Checks
- [ ] `GET /api/health` returns `200 OK` with `database.connected: true`.
- [ ] `GET /` renders Login / Dashboard shell cleanly with HTTPS & `Secure` cookie attributes.
- [ ] Sign in or register initial Owner account and rotate/remove seeded demo accounts if deploying outside sandbox/demo mode.
- [ ] Verify `GET /api/v1/audit-logs` reports `chainVerified: true`.
- [ ] Confirm `GET /api/v1/openapi.json` returns 40 documented endpoints.
