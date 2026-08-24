// ═══════════════════════════════════════════════════════════════════
// TODO.identity-ops/01 + /05 — the OIDC-surface CONTRACT GATE as an e2e
// leg: the identity-profile API boots on its own port + its own SQLite
// file (the id-01 spawned-stack pattern, API-only — every OP endpoint
// this probes is served by the Hono app, no astro and no browser
// needed), and scripts/op-surface-contract.ts captures the public
// surface (the discovery document, the JWKS shape, the unauthenticated
// error taxonomy) plus the CLAIMS CONTRACT (a full fetch-level round
// trip: demo sign-in → authorize → the consent context → the decision
// → the code exchange → the ID token + userinfo) and deep-compares it
// against the committed golden
// (browser/e2e/golden/op-surface-contract.golden.json).
//
// A breaking change to the OP's public surface fails HERE, in CI,
// before it can reach a Relying Party — and the same script's `probe`
// mode is the deploy pipeline's preview/production proof and the
// heartbeat's shape (docs/deployment/identity-deploy.md). An INTENDED
// surface change re-records the golden deliberately:
//
//   npx tsx scripts/op-surface-contract.ts record http://localhost:9693 \
//     --client-id fixture-rp --client-secret fixture-rp-secret \
//     --redirect-uri http://127.0.0.1:9694/callback \
//     --email ia@oiml.org --password demo2026
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdirSync, rmSync, readFileSync } from 'node:fs'
import { delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { captureSurface, assertSurfaceInvariants, diffSurface } from '../scripts/op-surface-contract'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'op-surface-contract')
const GOLDEN = join(BROWSER_DIR, 'e2e', 'golden', 'op-surface-contract.golden.json')

// Port-isolated: clear of the shared dev stack (5190/3190), the id-*
// stacks (8393..9596), the stub IdP (8699/8994), and the local identity
// dev stack (7390/7190).
const ID_API = 9693
const RP_CALLBACK_PORT = 9694

const ISSUER = `http://localhost:${ID_API}` // the API serves the OP surface directly (app.ts mounts the OP router at the root)
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'
const RP_REDIRECT_URI = `http://127.0.0.1:${RP_CALLBACK_PORT}/callback`

let api: ChildProcess | undefined
const logs: string[] = []

function killTreeHard(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGKILL') } catch { /* group already gone */ }
  try { proc.kill('SIGKILL') } catch { /* already gone */ }
}

async function waitForHttp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url)
      if (res.status < 500) return
      lastError = `HTTP ${res.status}`
    } catch (e) {
      lastError = String(e)
    }
    await delay(1_000)
  }
  throw new Error(`timed out waiting for ${url} (${lastError})\n--- stack logs ---\n${logs.join('').slice(-4000)}`)
}

beforeAll(async () => {
  mkdirSync(DB_DIR, { recursive: true })
  const dbPath = join(DB_DIR, 'identity.db')
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })

  try {
    const probe = await fetch(`http://localhost:${ID_API}/api/health`).catch(() => null)
    if (probe && probe.status < 500) throw new Error(`port ${ID_API} is already serving — a leftover stack? (kill it: lsof -ti tcp:${ID_API} | xargs kill)`)
  } catch (e) {
    if (e instanceof Error && e.message.includes('already serving')) throw e
  }

  // The tsx CLI directly (never npx — the wrapper orphans the server);
  // detached so the process group dies together; the env scrubs the
  // vitest markers (NODE_ENV=test would poison the spawned stack) and
  // the suite's SSO posture (OIDC_*) must NOT leak into the identity
  // instance (the id-01 lesson).
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => k !== 'NODE_ENV' && k !== 'VITEST' && !k.startsWith('VITEST_')),
  ) as NodeJS.ProcessEnv
  api = spawn(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
    cwd: BROWSER_DIR,
    env: {
      ...inherited,
      PORT: String(ID_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: ISSUER,
      // identity#7: a declared-issuer stack declares its signing key too
      // (the generated dev key never registers off the dev posture).
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      // The registry's bootstrap seed: the fixture RP (a confidential
      // client carrying the role-claim policy).
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The e2e fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [RP_REDIRECT_URI],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  })
  api.stdout?.on('data', d => logs.push(String(d)))
  api.stderr?.on('data', d => logs.push(String(d)))

  try {
    await waitForHttp(`${ISSUER}/api/health`, 120_000)
    // Provision the profile's seed (the demo cast + the instance admin).
    const reset = await fetch(`${ISSUER}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}\n${logs.join('').slice(-2000)}`)
  } catch (e) {
    killTreeHard(api)
    throw e
  }
}, 180_000)

afterAll(() => {
  killTreeHard(api)
})

describe('TODO.identity-ops — the OIDC-surface contract gate', () => {
  it('the public surface + the claims contract match the committed golden', { timeout: 240_000 }, async () => {
    const captured = await captureSurface(ISSUER, {
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
      redirectUri: RP_REDIRECT_URI,
      email: 'ia@oiml.org',
      password: 'demo2026',
    })

    // The invariants first (what the volatile markers must satisfy):
    const invariantProblems = assertSurfaceInvariants(captured, ISSUER)
    expect(invariantProblems, `surface invariants:\n${invariantProblems.join('\n')}`).toEqual([])

    // …then the golden itself: every drift path is a review line.
    const golden = JSON.parse(readFileSync(GOLDEN, 'utf8')) as unknown
    const diffs = diffSurface(golden, captured)
    expect(
      diffs,
      `the OIDC surface drifted from the committed golden:\n${diffs.join('\n')}\n` +
      'An INTENDED change re-records deliberately: npx tsx scripts/op-surface-contract.ts record ' +
      `${ISSUER} --client-id ${RP_CLIENT_ID} --client-secret ${RP_CLIENT_SECRET} --redirect-uri ${RP_REDIRECT_URI} --email ia@oiml.org --password demo2026`,
    ).toEqual([])
  })
})
