import crypto from 'node:crypto';
import type { NextRequest } from 'next/server';
import { getDb } from '@/lib/db';
import { sha256 } from '@/lib/security/crypto';

export function generateRunnerToken(): {
  rawToken: string;
  tokenPrefix: string;
  tokenHash: string;
} {
  const rawToken = `tr_run_${crypto.randomBytes(24).toString('hex')}`;
  return {
    rawToken,
    tokenPrefix: rawToken.slice(0, 15),
    tokenHash: sha256(rawToken),
  };
}

export interface AuthenticatedRunner {
  id: string;
  orgId: string;
  name: string;
  mode: 'scan' | 'cicd' | 'runtime_collector';
  status: string;
}

export function authenticateRunnerRequest(req: NextRequest): AuthenticatedRunner | null {
  const authHeader = req.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer tr_run_')) return null;
  const rawToken = authHeader.slice(7).trim();
  if (!rawToken) return null;

  const db = getDb();
  const row = db
    .prepare(
      `SELECT id, org_id as orgId, name, mode, status
       FROM runners WHERE token_hash = ? AND status != 'Revoked'`
    )
    .get(sha256(rawToken)) as AuthenticatedRunner | undefined;

  return row || null;
}

export function buildCiPipelineSnippets(apiUrl = 'https://your-trustrail.example.com') {
  return {
    githubActions: `name: Trustrail Security Gate
on: [pull_request, push]
jobs:
  trustrail-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - name: Run Trustrail Unified Scan & Policy Gate
        env:
          TRUSTRAIL_API_URL: ${apiUrl}
          TRUSTRAIL_TOKEN: \${{ secrets.TRUSTRAIL_API_KEY }}
        run: |
          npx tsx bin/trustrail.ts scan . --project \${{ github.repository }} --sync --fail-on-critical`,
    gitlabCi: `trustrail_security_gate:
  image: node:22-alpine
  stage: test
  variables:
    TRUSTRAIL_API_URL: ${apiUrl}
  script:
    - npx tsx bin/trustrail.ts scan . --project "$CI_PROJECT_PATH" --sync --fail-on-critical
  only:
    - merge_requests
    - main`,
    jenkins: `pipeline {
  agent any
  environment {
    TRUSTRAIL_API_URL = '${apiUrl}'
    TRUSTRAIL_TOKEN = credentials('trustrail-api-key')
  }
  stages {
    stage('Trustrail Security Gate') {
      steps {
        sh 'npx tsx bin/trustrail.ts scan . --project "$JOB_NAME" --sync --fail-on-critical'
      }
    }
  }
}`,
  };
}
