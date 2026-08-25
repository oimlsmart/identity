/**
 * deploy-instance.ts — deploy one identity env (an [env.<name>] block of
 * browser/wrangler.toml) with the RIGHT config.
 *
 * Why this exists (the 2026-08-15 lesson): `wrangler deploy --config
 * dist/server/wrangler.json --env <name>` does NOT apply the env
 * block — the @astrojs/cloudflare generated config carries the default
 * environment only, so the env deploy silently got the default
 * database, no INSTANCE_PROFILE_YAML, and no route discipline. This
 * script composes a per-env config from the generated build output +
 * the toml's env block, so name, D1 binding, and vars are exactly the
 * instance's. Routes are stripped: domains attach only via
 * cloudflare-domains.sh.
 *
 * Usage (from browser/):
 *   npx tsx scripts/deploy-instance.ts identity
 *   npx tsx scripts/deploy-instance.ts identity-preview
 *   npx tsx scripts/deploy-instance.ts identity --compose-only
 *     (compose dist/server/wrangler.<env>.json WITHOUT deploying — the
 *     CI bundle-shape dry leg and the rollback recipe's config source,
 *     docs/deployment/identity-deploy.md)
 *   npx tsx scripts/deploy-instance.ts selfhost --overlay wrangler.self-host.toml
 *     (the SELF-HOST path, TODO.self-host/02: the env block comes from an
 *     UNTRACKED overlay toml — the operator's own worker name, D1 ids,
 *     buckets, vars — so the tracked wrangler.toml stays the estate's
 *     deployment and a self-host deploy never edits a tracked file; the
 *     runbook is docs/deployment/identity-self-host.md)
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { parse } from 'smol-toml';

const env = process.argv[2];
const composeOnly = process.argv.includes('--compose-only');
// The env block's source: the tracked wrangler.toml (the estate's
// deployment) or an UNTRACKED overlay (`--overlay <path>` — the
// self-host path, never a tracked-file edit).
const overlayIdx = process.argv.indexOf('--overlay');
const overlay = overlayIdx >= 0 ? process.argv[overlayIdx + 1] : undefined;
if (overlayIdx >= 0 && !overlay) {
  console.error('--overlay needs a path (an untracked toml carrying your [env.<name>] block)');
  process.exit(1);
}
if (!env || env.startsWith('--')) {
  console.error('usage: npx tsx scripts/deploy-instance.ts <env-name> [--overlay <toml>] [--compose-only]  (an [env.<name>] block in wrangler.toml or the overlay)');
  process.exit(1);
}

const sourcePath = overlay ?? 'wrangler.toml';
if (overlay && !existsSync(overlay)) {
  console.error(`the overlay ${overlay} does not exist (the self-host runbook: docs/deployment/identity-self-host.md)`);
  process.exit(1);
}

const base = JSON.parse(readFileSync('dist/server/wrangler.json', 'utf8'));
const toml = parse(readFileSync(sourcePath, 'utf8'));
const block = toml?.env?.[env];
if (!block) {
  console.error(`no [env.${env}] block in ${sourcePath} (have: ${Object.keys(toml.env ?? {}).join(', ') || 'none'})`);
  process.exit(1);
}
if (!block.name || !block.d1_databases?.length) {
  console.error(`[env.${env}] must declare name + at least one d1 database`);
  process.exit(1);
}

const composed = {
  ...base,
  name: block.name,
  d1_databases: block.d1_databases,
  // The env block's OWN bindings must carry too (2026-08-17: the
  // composer's first version dropped r2_buckets, so the instances
  // silently bound the default bucket or none; 2026-08-24: the same
  // gap for send_email — smart#182 activated the EMAIL binding in
  // [env.identity] and the generated base config's `send_email: []`
  // silently won, so the deploy would have shipped WITHOUT it).
  ...(block.r2_buckets ? { r2_buckets: block.r2_buckets } : {}),
  ...(block.send_email ? { send_email: block.send_email } : {}),
  vars: { ...(base.vars ?? {}), ...(block.vars ?? {}) },
  routes: [],
  tail_consumers: [],
  configPath: `dist/server/wrangler.${env}.json`,
};

const out = `dist/server/wrangler.${env}.json`;
writeFileSync(out, JSON.stringify(composed, null, 2));
console.log(`composed ${out}: name=${composed.name}, d1=${composed.d1_databases.map((d) => d.database_name).join(',')}`);

if (composeOnly) {
  console.log('--compose-only: the config is written, nothing deployed');
  process.exit(0);
}

const run = spawnSync('npx', ['wrangler', 'deploy', '--config', out], { stdio: 'inherit' });
process.exit(run.status ?? 1);
