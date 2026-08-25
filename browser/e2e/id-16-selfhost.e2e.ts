// ═══════════════════════════════════════════════════════════════════
// TODO.self-host/03 — the SELF-HOST SMOKE PROOF (posture b of the four
// identity postures, smart's TODO.self-host/00): a third party clones
// oimlsmart/identity and boots THEIR OWN OP with ONLY environment
// configuration — no tracked-file edit, no fork. This leg IS that boot,
// and the runbook (docs/deployment/identity-self-host.md) cites it as
// the executable form of its Node + SQLite path.
//
// The boot is exactly the self-hoster's: the node API (server/serve.ts
// under tsx), a FRESH SQLite file in the OS temp dir (never the repo),
// and env config only — the declared loopback issuer, one bootstrap
// admin (OP_ACCOUNT_SEED), one test client (OP_CLIENT_SEED), one
// stub-IdP registry row (OP_UPSTREAM_SEED), a GENERATED ES256 signing
// key for the leg (fixtures/op-signing-key.ts — never the estate key),
// and an instance-profile YAML written to the temp dir (the ACME cast,
// demo_personas: false — the production posture). Explicitly NOT
// configured: the mailer and the avatar store — the leg asserts the
// HONEST degradations (the self-service reset answers the 503
// not-configured posture; the avatar routes 503 and /api/config
// reports blobs.available false, so the UI falls back to initials).
//
// API-only (the op-surface-contract pattern): every OP endpoint this
// drives is served by the Hono app, so no astro and no browser — real
// HTTP on every hop.
//
//   leg 1  the OIDC surface on the loopback issuer: the discovery
//          document names OUR issuer and endpoints, the JWKS carries
//          the leg's own kid, token/userinfo refuse honestly;
//   leg 2  the bootstrap story: the seeded admin's one-time setup link
//          lands in the DEPLOY LOG (the operator's way in on a fresh
//          OP), the enroll endpoints answer its context and complete
//          the password, and the spent link is honestly dead (410);
//   leg 3  the sign-in round trip: the admin's password sign-in, the
//          authorization-code + PKCE flow for the seeded client, the
//          code exchange, and the ID token validated by the kernel's
//          REAL RP validator over the leg's own JWKS, plus userinfo;
//   leg 4  the registry is the operator's: the admin API accepts a new
//          client (201, server-generated secret), lists it, refuses the
//          anonymous caller (401), and the login projection
//          (/api/op/providers/public) carries the seeded upstream row;
//   leg 5  the honest degradations: no mailer → the self-service reset
//          503s with mailAvailable:false; no blob store → the avatar
//          upload 503s with available:false and /api/config says so;
//          the demo cast is CLOSED (demo_personas: false → the demo
//          sign-in 403s);
//   leg 6  the checkout stayed clean: `git status --porcelain` after
//          the boot is byte-identical with the snapshot taken before —
//          the boot writes NOTHING into the checkout (the SQLite file
//          and the profile YAML live in the OS temp dir). On CI's clean
//          checkout the before-snapshot is empty, so the equality IS
//          the spec's empty assertion; the equality form stays honest
//          in a shared checkout carrying other waves' uncommitted work.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched.
// Port-isolated: API 10393 — clear of every live leg (id-01's
// 8693/8393/8694, id-02's 8793/8593/8794, id-03's 9393/9293/9294,
// id-04's 9492/9493/9494, id-05's 9592/9593/9596, id-06's 9493/9393,
// id-07's 9293/9294, id-08's 8993/8893/8994, id-09's 8795/8595,
// id-10's 9193/9093, id-11's 9893/9894, id-12's 10093/10094/10095,
// id-13's 9993/9994, id-14's 10193/10194/10195, id-15's 10293/10294,
// the surface legs' 9793/9693, the contract gate's 9693/9694,
// op-key-rotate's 9695). 10394/10395 are ADDRESS-ONLY (the
// registered redirect_uri and the stub-IdP issuer) — nothing binds them:
// the code lands on the redirect URL the consent decision answers, and
// the upstream row is asserted on the login projection, never flowed.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { generatePkce, validateIdToken, clearOidcCaches } from '@oimlsmart/platform-server/oidc'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const REPO_ROOT = resolve(BROWSER_DIR, '..')

const ID_API = 10393
const RP_REDIRECT_URI = 'http://127.0.0.1:10394/callback' // address-only (never bound)
const STUB_IDP_ISSUER = 'http://127.0.0.1:10395' // address-only (never bound)

const ISSUER = `http://127.0.0.1:${ID_API}` // loopback is the test posture
const ADMIN = { email: 'admin@id.example.invalid', name: 'Ada Example' }
const ADMIN_PASSWORD = 'acme bootstrap passphrase 2026'
const RP_CLIENT_ID = 'acme-app'
const RP_CLIENT_SECRET = 'acme-app-leg-secret'

let api: ChildProcess | undefined
let tmp: string
let gitBefore = ''
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

/** The checkout's dirty list (untracked included). The claim under test:
 *  the boot adds NOTHING to it. */
function gitStatus(): string {
  return execFileSync('git', ['status', '--porcelain'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim()
}

/** The seeded admin's one-time setup link, scraped from the deploy log —
 *  exactly where a self-hoster reads it on a fresh boot (the seed logs
 *  it once per process until the password is set, auth/op/accounts.ts). */
async function scrapeSetupUrl(): Promise<string> {
  const deadline = Date.now() + 30_000
  while (Date.now() < deadline) {
    const match = logs.join('').match(/\/op\/setup\?token=([^\s]+)/)
    if (match) return `${ISSUER}/op/setup?token=${match[1]}`
    await delay(500)
  }
  throw new Error(`the bootstrap setup link never landed in the deploy log\n--- stack logs ---\n${logs.join('').slice(-4000)}`)
}

beforeAll(async () => {
  gitBefore = gitStatus()
  tmp = mkdtempSync(join(tmpdir(), 'id-16-selfhost-'))
  const dbPath = join(tmp, 'registry.db')

  // The instance profile is CONFIGURATION (the program's rule: env vars,
  // the profile YAML, the seed declarations) — so it lives in the temp
  // dir too, proving the seam reads from OUTSIDE the checkout. The ACME
  // cast, the demo cast OFF (the production posture).
  const profilePath = join(tmp, 'instance.profile.yaml')
  writeFileSync(profilePath, `# the self-hoster's own profile (id-16: temp-dir configuration)
identity:
  org_id: acme-id
  org_name: ACME Identity
  role_codes: [identity]
roles: [identity]
branding:
  name: ACME Identity
demo_personas: false
`)

  try {
    const probe = await fetch(`http://127.0.0.1:${ID_API}/api/health`).catch(() => null)
    if (probe && probe.status < 500) throw new Error(`port ${ID_API} is already serving — a leftover stack? (kill it: lsof -ti tcp:${ID_API} | xargs kill)`)
  } catch (e) {
    if (e instanceof Error && e.message.includes('already serving')) throw e
  }

  // The tsx CLI directly (never npx — the wrapper orphans the server);
  // detached so the process group dies together. The env scrubs the
  // vitest markers (NODE_ENV=test would poison the spawned stack) AND
  // everything that could leak a developer's own posture into the leg:
  // the RP-side OIDC_*, the OP_* declarations, and the mailer/avatar
  // envs — the degradation asserts below are only honest when NOTHING
  // configures them.
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([k]) =>
      k !== 'NODE_ENV' && !k.startsWith('VITEST_') && k !== 'VITEST'
      && !k.startsWith('OIDC_') && !k.startsWith('OP_')
      && !k.startsWith('MAIL_') && !k.startsWith('EMAIL_') && !k.startsWith('BLOBS_')),
  ) as NodeJS.ProcessEnv
  api = spawn(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
    cwd: BROWSER_DIR,
    env: {
      ...inherited,
      PORT: String(ID_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: profilePath,
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'false',
      OP_ISSUER: ISSUER,
      // identity#7: a declared-issuer stack declares its signing key too —
      // a FRESH ES256 pair for the leg (never the estate key, never a
      // checked-in key).
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      // The bootstrap admin (the first administrator arrives by
      // declaration — a fresh OP has no accounts and no open signup).
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ADMIN.email, name: ADMIN.name, role: 'admin' }]),
      // One test client (the self-hoster's own RP).
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The ACME application',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [RP_REDIRECT_URI],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
      // One upstream sign-in provider row (the staff IdP stub — the row
      // only; the flow itself is id-08's proof).
      OP_UPSTREAM_SEED: JSON.stringify([{
        id: 'acme-staff',
        kind: 'oidc',
        display_name: 'ACME Staff SSO',
        issuer: STUB_IDP_ISSUER,
        client_id: 'op-at-acme-staff',
        client_secret_ref: 'env:ACME_STAFF_CLIENT_SECRET',
      }]),
      // The honest degradation postures: no mailer (the envs stay
      // undeclared), no avatar store.
      BLOBS_DISABLED: 'true',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  })
  api.stdout?.on('data', d => logs.push(String(d)))
  api.stderr?.on('data', d => logs.push(String(d)))

  try {
    await waitForHttp(`${ISSUER}/api/health`, 120_000)
    // Trip the bootstraps. Each seed rides its OWN router's
    // once-per-process seam (a sub-app's /api/op/* middleware does not
    // cross into a sibling router mounted at the same base — verified
    // 2026-08-25): the providers projection seeds the upstream registry,
    // and any op-accounts route (the enroll probe below answers an
    // honest 404) seeds the accounts + the client registry. A real
    // deployment's first sign-in-page round trip trips the same seams —
    // the seeds are lazy and idempotent. NO dev-reset, no demo cast — a
    // self-hoster's boot has neither.
    const providers = await fetch(`${ISSUER}/api/op/providers/public`)
    if (!providers.ok) throw new Error(`the login projection answered ${providers.status}\n${logs.join('').slice(-2000)}`)
    const enrollProbe = await fetch(`${ISSUER}/api/op/enroll/selfhost-seed-probe`)
    if (enrollProbe.status !== 404) throw new Error(`the enroll seed-probe answered ${enrollProbe.status}, expected the honest 404`)
  } catch (e) {
    killTreeHard(api)
    throw e
  }
}, 180_000)

afterAll(() => {
  killTreeHard(api)
  if (tmp) rmSync(tmp, { recursive: true, force: true })
})

describe('TODO.self-host/03 — the self-host smoke proof (configuration-only boot)', () => {
  it('leg 1 — the OIDC surface answers on the loopback issuer with the leg’s own key', { timeout: 120_000 }, async () => {
    const meta = await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json() as Record<string, string>
    expect(meta.issuer).toBe(ISSUER)
    expect(meta.authorization_endpoint).toBe(`${ISSUER}/op/authorize`)
    expect(meta.token_endpoint).toBe(`${ISSUER}/op/token`)
    expect(meta.userinfo_endpoint).toBe(`${ISSUER}/op/userinfo`)
    expect(meta.jwks_uri).toBe(`${ISSUER}/jwks.json`)

    // The JWKS carries the LEG's kid (the generated pair), never an
    // estate key.
    const legKid = (JSON.parse(await fixtureOpSigningKey()) as { kid: string }).kid
    const jwks = await (await fetch(meta.jwks_uri)).json() as { keys: Array<Record<string, unknown>> }
    expect(jwks.keys.length).toBeGreaterThanOrEqual(1)
    expect(jwks.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid: legKid })

    // The declared endpoints are really served, refusing honestly.
    const tokenProbe = await fetch(meta.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=none' })
    expect(tokenProbe.status).toBe(400)
    const userinfoProbe = await fetch(meta.userinfo_endpoint)
    expect(userinfoProbe.status).toBe(401)
  })

  it('leg 2 — the bootstrap story: the seeded admin’s one-time setup link completes, then dies', { timeout: 120_000 }, async () => {
    const setupUrl = await scrapeSetupUrl()
    expect(setupUrl).toContain(`${ISSUER}/op/setup?token=`)
    const token = new URL(setupUrl).searchParams.get('token')!

    // The setup page's context (public, name/email only).
    const context = await fetch(`${ISSUER}/api/op/enroll/${token}`)
    expect(context.status).toBe(200)
    expect(await context.json()).toMatchObject({ email: ADMIN.email, name: ADMIN.name })

    // The completion sets the password and opens the first session.
    const complete = await fetch(`${ISSUER}/api/op/enroll/${token}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: ADMIN_PASSWORD }),
    })
    expect(complete.status).toBe(200)
    expect(complete.headers.get('set-cookie')).toContain('oiml-session=')

    // One-time means one-time: the spent link is honestly dead.
    const replay = await fetch(`${ISSUER}/api/op/enroll/${token}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'another passphrase entirely' }),
    })
    expect(replay.status).toBe(410)
  })

  it('leg 3 — the sign-in round trip: password sign-in, the code flow, the RP-validated token, userinfo', { timeout: 240_000 }, async () => {
    // The password sign-in (the OP's own account model — the demo cast
    // is closed on this posture, leg 5 proves it).
    const login = await fetch(`${ISSUER}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ADMIN.email, password: ADMIN_PASSWORD }),
    })
    expect(login.status).toBe(200)
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!

    // The authorization-code + PKCE round trip for the seeded client
    // (the fetch-level shape, the contract gate's pattern).
    const pkce = await generatePkce()
    const nonce = 'selfhost-nonce-16'
    const authorize = await fetch(`${ISSUER}/op/authorize?${new URLSearchParams({
      response_type: 'code', client_id: RP_CLIENT_ID, redirect_uri: RP_REDIRECT_URI,
      scope: 'openid profile email', state: 'selfhost-state', nonce,
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
    })}`, { headers: { cookie }, redirect: 'manual' })
    expect(authorize.status).toBe(302)
    const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!

    const consent = await fetch(`${ISSUER}/api/op/consent/${authId}`, { headers: { cookie } })
    expect(consent.status).toBe(200)
    expect(await consent.json()).toMatchObject({ client: { name: 'The ACME application' } })

    const decide = await fetch(`${ISSUER}/api/op/consent/${authId}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    expect(decide.status).toBe(200)
    const { redirect } = await decide.json() as { redirect: string }
    const redirectUrl = new URL(redirect)
    expect(redirectUrl.origin).toBe('http://127.0.0.1:10394') // the SEEDED redirect_uri
    const code = redirectUrl.searchParams.get('code')!

    const exchange = await fetch(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${btoa(`${encodeURIComponent(RP_CLIENT_ID)}:${encodeURIComponent(RP_CLIENT_SECRET)}`)}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code, redirect_uri: RP_REDIRECT_URI,
        client_id: RP_CLIENT_ID, code_verifier: pkce.verifier,
      }),
    })
    expect(exchange.status).toBe(200)
    const tokens = await exchange.json() as { access_token: string; id_token: string }

    // The kernel's REAL RP validator accepts the leg's ID token against
    // the leg's own JWKS (signature, iss/aud/exp/nonce).
    clearOidcCaches()
    const claims = await validateIdToken(tokens.id_token, {
      issuer: ISSUER, clientId: RP_CLIENT_ID, nonce, jwksUri: `${ISSUER}/jwks.json`,
    })
    expect(claims.iss).toBe(ISSUER)
    expect(claims.aud).toBe(RP_CLIENT_ID)
    expect(claims.email).toBe(ADMIN.email)
    expect(claims.name).toBe(ADMIN.name)

    const userinfo = await fetch(`${ISSUER}/op/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
    expect(userinfo.status).toBe(200)
    expect(await userinfo.json()).toMatchObject({ email: ADMIN.email, name: ADMIN.name })
  })

  it('leg 4 — the registry is the operator’s: the admin API accepts a client, the login projection shows the seed', { timeout: 120_000 }, async () => {
    const login = await fetch(`${ISSUER}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ADMIN.email, password: ADMIN_PASSWORD }),
    })
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!

    // The registry is admin-held: the anonymous caller is refused.
    expect((await fetch(`${ISSUER}/api/op/clients`)).status).toBe(401)

    // A new client through the admin API (the server-generated-secret
    // posture — the plaintext rides the response once).
    const created = await fetch(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({
        client_id: 'acme-second-app',
        name: 'The second ACME application',
        generate_secret: true,
        redirect_uris: ['http://127.0.0.1:10394/second-callback'],
      }),
    })
    expect(created.status).toBe(201)
    const createdBody = await created.json() as { clientId: string; secret?: string; confidential: boolean }
    expect(createdBody.clientId).toBe('acme-second-app')
    expect(createdBody.confidential).toBe(true)
    expect(createdBody.secret).toBeTruthy()

    const registry = await (await fetch(`${ISSUER}/api/op/clients`, { headers: { cookie } })).json() as Array<{ clientId: string }>
    expect(registry.map(c => c.clientId).sort()).toEqual([RP_CLIENT_ID, 'acme-second-app'].sort())

    // The login projection (the sign-in page's provider buttons) carries
    // the seeded upstream row — public fields only, never the secret ref.
    const providers = await (await fetch(`${ISSUER}/api/op/providers/public`)).json() as Array<Record<string, unknown>>
    expect(providers).toContainEqual({ id: 'acme-staff', kind: 'oidc', displayName: 'ACME Staff SSO', brandMark: null })
    expect(JSON.stringify(providers)).not.toContain('ACME_STAFF_CLIENT_SECRET')
  })

  it('leg 5 — the honest degradations: no mailer, no avatar store, no demo cast', { timeout: 120_000 }, async () => {
    // No mail provider configured → the self-service reset answers the
    // honest 503 and points at the administrator (never a silent drop,
    // never an account-takeover door).
    const reset = await fetch(`${ISSUER}/api/op/login/reset`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ADMIN.email }),
    })
    expect(reset.status).toBe(503)
    expect(await reset.json()).toMatchObject({ mailAvailable: false })

    // No blob store bound → the avatar upload 503s honestly (the account
    // shows the linked provider's picture, or the initials).
    const login = await fetch(`${ISSUER}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ADMIN.email, password: ADMIN_PASSWORD }),
    })
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!
    const avatar = await fetch(`${ISSUER}/api/op/account/avatar`, {
      method: 'PUT',
      headers: { cookie, 'content-type': 'image/png' },
      body: new Uint8Array([0x89, 0x50, 0x4e, 0x47]),
    })
    expect(avatar.status).toBe(503)
    expect(await avatar.json()).toMatchObject({ available: false })

    // …and /api/config says both postures to the pages: no blob store,
    // no demo cast (demo_personas: false — the production posture).
    const config = await (await fetch(`${ISSUER}/api/config`)).json() as { blobs: { available: boolean }; identity: { demoAccountsEnabled: boolean } }
    expect(config.blobs.available).toBe(false)
    expect(config.identity.demoAccountsEnabled).toBe(false)
    const demo = await fetch(`${ISSUER}/api/auth/demo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ADMIN.email, password: 'demo2026' }),
    })
    expect(demo.status).toBe(403)
  })

  it('leg 6 — the boot wrote NOTHING into the checkout', { timeout: 60_000 }, async () => {
    // Byte-identical dirty lists (see the header): on CI's clean
    // checkout this is the spec's empty assertion exactly.
    expect(gitStatus(), 'the self-host boot added files to the checkout').toBe(gitBefore)
  })
})
