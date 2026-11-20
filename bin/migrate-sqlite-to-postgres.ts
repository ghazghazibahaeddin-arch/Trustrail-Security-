#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const TABLES_IN_DEPENDENCY_ORDER = [
  'organizations',
  'users',
  'memberships',
  'projects',
  'assets',
  'graph_edges',
  'scans',
  'findings',
  'change_contracts',
  'policies',
  'ai_agents',
  'incidents',
  'canaries',
  'compliance_controls',
  'connectors',
  'api_keys',
  'trust_receipts',
  'remediation_runs',
  'recovery_backups',
  'cloud_resources',
  'audit_logs',
];

function escapeSqlLiteral(val: unknown): string {
  if (val === null || val === undefined) return 'NULL';
  if (typeof val === 'number') return Number.isFinite(val) ? String(val) : 'NULL';
  if (typeof val === 'boolean') return val ? 'TRUE' : 'FALSE';
  const s = String(val).replace(/'/g, "''");
  return `'${s}'`;
}

function main() {
  const dbPath = process.env.TRUSTRAIL_DB_PATH || path.join(process.cwd(), '.data', 'trustrail.db');
  const outPath = process.argv[2] || path.join(process.cwd(), '.data', 'trustrail-postgres-export.sql');

  if (!fs.existsSync(dbPath)) {
    console.error(`SQLite database not found at ${dbPath}`);
    process.exit(1);
  }

  const db = new DatabaseSync(dbPath, { readOnly: true });
  const schemaSql = fs.readFileSync(path.join(process.cwd(), 'lib/db/postgres-schema.sql'), 'utf8');
  const statements: string[] = [
    '-- TRUSTRAIL SQLite -> PostgreSQL Migration Export',
    `-- Generated at ${new Date().toISOString()}`,
    'BEGIN;',
    schemaSql,
  ];

  let exportedRows = 0;
  for (const table of TABLES_IN_DEPENDENCY_ORDER) {
    const rows = db.prepare(`SELECT * FROM ${table}`).all() as Array<Record<string, unknown>>;
    for (const row of rows) {
      const cols = Object.keys(row);
      const vals = cols.map((c) => escapeSqlLiteral(row[c]));
      statements.push(
        `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${vals.join(', ')}) ON CONFLICT DO NOTHING;`
      );
      exportedRows += 1;
    }
  }

  statements.push('COMMIT;');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, statements.join('\n'), 'utf8');
  console.log(JSON.stringify({ exportedRows, outPath, tables: TABLES_IN_DEPENDENCY_ORDER.length }, null, 2));
}

main();
