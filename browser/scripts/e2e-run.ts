// ─────────────────────────────────────────────────────────────────────
// The e2e runner — isolation rules, two callers (npm run test:e2e and
// the from-packages proof).
//
// The suite runs SERIAL (vitest.e2e.config.ts: fileParallelism: false)
// against ONE shared dev server, so files must never inherit each
// other's entity state. Two rules make that real:
//
// 1. render-baseline.e2e.ts always runs FIRST, alone: it compares page
//    text against a recorded PRISTINE-state baseline, before anything
//    mutates.
// 2. Every flow file runs in its own vitest invocation, preceded by a
//    POST to /api/dev-reset (TODO.FULL/01): the server's mutable stores
//    are wiped and reseeded, so each file starts from the same pristine
//    provisioning. The pollution classes this kills: shared declarations
//    (cnml-issue vs participant-registry), shared awaiting-issuance
//    evaluations (biml-portal vs cnml-issue), shared certificate
//    register state (cs-operations vs everything).
//
// A file that cannot pass from the pristine seed is a hermeticity bug in
// the test — it fails loudly here, never masked by another file's
// leftovers.
//
// Usage: npx tsx scripts/e2e-run.ts [files…]   (no args = the full e2e set)
// Env:   E2E_BASE_URL (default http://localhost:5190) is passed through.
// ─────────────────────────────────────────────────────────────────────

import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const BROWSER = dirname(fileURLToPath(import.meta.url)) + '/..';
const BASELINE = 'e2e/render-baseline.e2e.ts';
const BASE = process.env.E2E_BASE_URL ?? 'http://localhost:5190';

const args = process.argv.slice(2);
const files =
  args.length > 0
    ? args
    : readdirSync(join(BROWSER, 'e2e'))
        .filter((f) => f.endsWith('.e2e.ts'))
        .sort()
        .map((f) => `e2e/${f}`);

const baseline = files.filter((f) => f.endsWith('render-baseline.e2e.ts'));
const rest = files.filter((f) => !f.endsWith('render-baseline.e2e.ts'));

async function resetServerState(): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${BASE}/api/dev-reset`, { method: 'POST' });
  } catch {
    console.error(`\x1b[31m✗ cannot reach ${BASE}/api/dev-reset — is the dev server up (npm run dev)?\x1b[0m`);
    process.exit(1);
  }
  if (!res.ok) {
    console.error(
      `\x1b[31m✗ dev-reset answered ${res.status} — the running server predates the isolation seam (TODO.FULL/01); restart npm run dev\x1b[0m`,
    );
    process.exit(1);
  }
}

function runFile(label: string, file: string): void {
  console.log(`\x1b[1m━━ e2e ${label}: ${file} ━━\x1b[0m`);
  const r = spawnSync('npx', ['vitest', 'run', '--config', 'vitest.e2e.config.ts', file], {
    cwd: BROWSER,
    env: process.env,
    stdio: 'inherit',
  });
  if (r.status !== 0) {
    console.error(`\x1b[31m✗ e2e ${label} failed at ${file} (exit ${r.status})\x1b[0m`);
    process.exit(r.status ?? 1);
  }
}

// Phase 1 — the baseline, on a guaranteed-pristine store.
if (baseline.length > 0) {
  await resetServerState();
  for (const f of baseline) runFile('phase 1 — render baseline (pristine server state)', f);
}

// Phase 2 — every flow file, each from a freshly reseeded store.
for (const f of rest) {
  await resetServerState();
  runFile('phase 2 — isolated flow file', f);
}

console.log('\x1b[32m✓ e2e suite green\x1b[0m');
