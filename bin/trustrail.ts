#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { executeUnifiedScan, scanTerraformAndIaC } from '../lib/engines/scanner-engine';
import { TrustrailClient } from '../lib/sdk/trustrail-client';

function printUsage() {
  console.log(`Trustrail Security Cloud CLI v1.1.0

Usage:
  trustrail scan <targetPath> [--project <name>] [--sync --url <apiUrl> --token <bearer>]
  trustrail terraform-check <tfFileOrPlanJson> [--url <apiUrl> --token <bearer>]
  trustrail sbom --projectId <id> [--format cyclonedx|spdx] [--url <apiUrl>] [--token <bearer>]
  trustrail findings [--url <apiUrl>] [--token <bearer>] [--severity <CRITICAL|HIGH|MEDIUM|LOW>]
  trustrail graph [--url <apiUrl>] [--token <bearer>]
  trustrail remediate <findingId> [--url <apiUrl>] [--token <bearer>]
  trustrail attest --title <title> [--url <apiUrl>] [--token <bearer>]
`);
}

function getFlag(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1 && args[idx + 1]) return args[idx + 1];
  return undefined;
}

function collectFiles(targetPath: string): {
  codeFiles: Array<{ path: string; content: string }>;
  packageJson?: string;
  terraform?: string;
  dockerfile?: string;
} {
  const resolved = path.resolve(targetPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Target path does not exist: ${resolved}`);
  }

  const stat = fs.statSync(resolved);
  const files: string[] = [];

  const walk = (dir: string, depth = 0) => {
    if (depth > 3 || files.length >= 25) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === '.next') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, depth + 1);
      } else {
        files.push(full);
      }
    }
  };

  if (stat.isDirectory()) {
    walk(resolved);
  } else {
    files.push(resolved);
  }

  const codeFiles: Array<{ path: string; content: string }> = [];
  let packageJson: string | undefined;
  let terraform: string | undefined;
  let dockerfile: string | undefined;

  for (const f of files) {
    const base = path.basename(f);
    const content = fs.readFileSync(f, 'utf8');
    if (base === 'package.json' && !packageJson) {
      packageJson = content;
    } else if ((base.endsWith('.tf') || base.endsWith('.tfplan.json')) && !terraform) {
      terraform = content;
    } else if (base === 'Dockerfile' && !dockerfile) {
      dockerfile = content;
    } else if (/\.(ts|tsx|js|jsx|py|go|rb)$/.test(base)) {
      codeFiles.push({ path: path.relative(process.cwd(), f), content });
    }
  }

  return { codeFiles, packageJson, terraform, dockerfile };
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (!cmd || cmd === '--help' || cmd === '-h') {
    printUsage();
    process.exit(0);
  }

  const apiUrl = getFlag(args, '--url') || process.env.TRUSTRAIL_API_URL || 'http://127.0.0.1:3000';
  const token = getFlag(args, '--token') || process.env.TRUSTRAIL_TOKEN;

  if (cmd === 'scan') {
    const target = args[1] || '.';
    const projectName = getFlag(args, '--project') || path.basename(path.resolve(target));
    const collected = collectFiles(target);

    const primaryCode = collected.codeFiles[0];
    const result = executeUnifiedScan({
      projectName,
      codeContent: collected.codeFiles.map((c) => `// FILE: ${c.path}\n${c.content}`).join('\n'),
      filePath: primaryCode?.path || target,
      packageJsonContent: collected.packageJson,
      terraformContent: collected.terraform,
      dockerfileContent: collected.dockerfile,
    });

    if (args.includes('--sync') && token) {
      const client = new TrustrailClient({ baseUrl: apiUrl, token });
      await client.runScan({
        projectName,
        codeContent: collected.codeFiles.map((c) => c.content).join('\n'),
        filePath: primaryCode?.path,
        packageJsonContent: collected.packageJson,
        terraformContent: collected.terraform,
        dockerfileContent: collected.dockerfile,
      });
    }

    console.log(
      JSON.stringify(
        {
          project: projectName,
          scannersRun: result.scannersRun,
          filesScanned: collected.codeFiles.length + (collected.packageJson ? 1 : 0) + (collected.terraform ? 1 : 0) + (collected.dockerfile ? 1 : 0),
          findingsCount: result.findings.length,
          sbomGenerated: Boolean(result.sbom),
          findings: result.findings,
        },
        null,
        2
      )
    );
    const hasCritical = result.findings.some((f) => f.severity === 'CRITICAL');
    process.exit(hasCritical && args.includes('--fail-on-critical') ? 2 : 0);
  }

  if (cmd === 'terraform-check') {
    const tfFile = args[1];
    if (!tfFile) {
      console.error('Missing Terraform file or plan JSON path.');
      process.exit(1);
    }
    const content = fs.readFileSync(path.resolve(tfFile), 'utf8');
    const res = scanTerraformAndIaC(content, path.basename(tfFile));
    console.log(JSON.stringify(res, null, 2));
    process.exit(res.findings.some((f) => f.severity === 'CRITICAL') && args.includes('--fail-on-critical') ? 2 : 0);
  }

  if (!token) {
    console.error('Missing API token. Pass --token <bearer> or set TRUSTRAIL_TOKEN.');
    process.exit(1);
  }

  const client = new TrustrailClient({ baseUrl: apiUrl, token });

  if (cmd === 'findings') {
    const severity = getFlag(args, '--severity');
    const res = await client.listFindings({ severity });
    console.log(JSON.stringify(res, null, 2));
    process.exit(0);
  }

  if (cmd === 'graph') {
    const res = await client.getGraph();
    console.log(JSON.stringify(res, null, 2));
    process.exit(0);
  }

  if (cmd === 'sbom') {
    const projectId = getFlag(args, '--projectId');
    const format = getFlag(args, '--format') === 'spdx' ? 'spdx' : 'cyclonedx';
    if (!projectId) {
      console.error('Missing --projectId <id>.');
      process.exit(1);
    }
    const res = await client.getProjectSbom(projectId, format, true);
    console.log(JSON.stringify(res, null, 2));
    process.exit(0);
  }

  if (cmd === 'remediate') {
    const findingId = args[1];
    if (!findingId) {
      console.error('Missing <findingId>.');
      process.exit(1);
    }
    const res = await client.startRemediation(findingId);
    console.log(JSON.stringify(res, null, 2));
    process.exit(0);
  }

  if (cmd === 'attest') {
    const title = getFlag(args, '--title') || 'CLI Security Posture Attestation';
    const res = await client.issueTrustPassport(title, ['SAST/SCA Verified', 'Policy Guardrails Active']);
    console.log(JSON.stringify(res, null, 2));
    process.exit(0);
  }

  console.error(`Unknown command: ${cmd}`);
  printUsage();
  process.exit(1);
}

main().catch((err) => {
  console.error(`Trustrail CLI Error: ${(err as Error).message}`);
  process.exit(1);
});
