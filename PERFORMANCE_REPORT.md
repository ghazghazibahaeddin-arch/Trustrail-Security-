# TRUSTRAIL Security Cloud — Performance Benchmark Report

**Audit Date:** 2026-11-19  
**Test Harness:** `tests/performance/benchmark.test.ts` (`vitest run`)  
**Runtime:** Node.js `v22.23.2` + `node:sqlite` (WAL mode)

## 1. Measured Latency Results
| Benchmark Workload | Iterations | Measured p95 Latency | Target SLO | Result |
| :--- | :--- | :--- | :--- | :--- |
| **Unified Multi-Scanner Sweep** (`SAST + Secret + SCA/SBOM + Terraform IaC`) | 50 | **0.46 ms** | `< 50 ms` | **PASS** |
| **Attack Path BFS Graph Solver** (100 synthetic assets, 99 directed edges) | 50 | **0.20 ms** | `< 50 ms` | **PASS** |
| **Authenticated API Handler Pair** (`GET /api/v1/findings` + `GET /api/v1/graph` w/ SQLite + Risk Scoring + Attack Paths) | 30 | **7.35 ms** | `< 150 ms` | **PASS** |

## 2. Architectural Observations
- **Zero Blocking Startup I/O:** Database schema migration (`runMigrations`) and idempotent seeding (`seedInitialData`) execute once per database handle (`getDb()`), keeping subsequent queries fast.
- **SQLite Concurrency:** Enabled `PRAGMA journal_mode = WAL;` and `PRAGMA busy_timeout = 5000;` (`lib/db.ts:28-30`) to prevent `SQLITE_BUSY` lock contention across concurrent Next.js App Router route bundles.
- **Scale Notes:** In-memory BFS attack path synthesis runs sub-millisecond up to 100+ nodes; for 10,000+ asset enterprise tenants, pre-computing/caching `attack_paths` snapshots on write events (scans/finding mutations) is recommended in future scale phases.
