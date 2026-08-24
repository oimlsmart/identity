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
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { parse } from 'smol-toml';

const env = process.argv[2];
const composeOnly = process.argv.includes('--compose-only');
if (!env) {
  console.error('usage: npx tsx scripts/deploy-instance.ts <env-name>  (an [env.<name>] block in wrangler.toml)');
  process.exit(1);
}

const base = JSON.parse(readFileSync('dist/server/wrangler.json', 'utf8'));
const toml = parse(readFileSync('wrangler.toml', 'utf8'));
const block = toml?.env?.[env];
if (!block) {
  console.error(`no [env.${env}] block in wrangler.toml (have: ${Object.keys(toml.env ?? {}).join(', ') || 'none'})`);
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
