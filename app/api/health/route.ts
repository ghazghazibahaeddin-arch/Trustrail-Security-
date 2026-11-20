import { getDb } from '@/lib/db';
import { getActiveVaultKeyVersion } from '@/lib/security/vault';
import { jsonOk, jsonError } from '@/lib/api-response';

export async function GET() {
  try {
    const db = getDb();
    const migration = db
      .prepare('SELECT MAX(version) as version FROM schema_migrations')
      .get() as { version: number | null };

    const orgCount = db
      .prepare('SELECT COUNT(*) as cnt FROM organizations')
      .get() as { cnt: number };

    const queuedJobs = db
      .prepare("SELECT COUNT(*) as cnt FROM background_jobs WHERE status = 'Queued'")
      .get() as { cnt: number };
    const dlqJobs = db
      .prepare("SELECT COUNT(*) as cnt FROM background_jobs WHERE status = 'Dead_Letter'")
      .get() as { cnt: number };

    return jsonOk({
      status: 'ok',
      timestamp: new Date().toISOString(),
      database: {
        engine: 'sqlite',
        connected: true,
        schemaVersion: migration?.version ?? 0,
        organizationsCount: orgCount.cnt,
      },
      vault: {
        algorithm: 'AES-256-GCM',
        activeKeyVersion: getActiveVaultKeyVersion(),
        envKeyConfigured: Boolean(process.env.TRUSTRAIL_VAULT_KEY),
      },
      jobQueue: {
        queued: queuedJobs.cnt,
        deadLetter: dlqJobs.cnt,
      },
      scanners: {
        sast: true,
        secretScanner: true,
        scaMultiEcosystem: true,
        iacTerraform: true,
        containerOci: true,
        cicdWorkflows: true,
      },
      integrations: {
        geminiConfigured: Boolean(process.env.GEMINI_API_KEY),
        githubConfigured: Boolean(process.env.GITHUB_TOKEN),
        githubWebhookSecretConfigured: Boolean(process.env.GITHUB_WEBHOOK_SECRET),
        awsConfigured: Boolean(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY),
        azureConfigured: Boolean(process.env.AZURE_ACCESS_TOKEN),
        gcpConfigured: Boolean(process.env.GCP_ACCESS_TOKEN),
        slackConfigured: Boolean(process.env.SLACK_WEBHOOK_URL),
      },
    });
  } catch (err) {
    return jsonError(
      `Health check failed: ${(err as Error).message}`,
      500,
      'HEALTH_CHECK_FAILED'
    );
  }
}

