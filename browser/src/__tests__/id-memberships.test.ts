// ─────────────────────────────────────────────────────────────────────
// TODO.identity/11 — the multi-organization membership model, proven
// in-process: the REAL routers (op, op-accounts, op-join,
// op-memberships, op-registry, users) over a REAL temp SQLite store,
// with the seeded participants register (the entity store).
//
// Covered:
//   THE BACKFILL's verification — migration 0011 applied onto a
//     pre-0011 database creates every org-bound account's PRIMARY
//     membership from the legacy columns (and the dual-read fallback:
//     an account with NO membership row reads exactly as before);
//   THE LIFECYCLE — invite (an existing account) → the holder's accept
//     → active → disabled → re-activated, with the stamps;
//   THE CONTEXT SWITCH — the session's active-org decides the claims:
//     the OIDC round trip's ID token + userinfo carry the ACTIVE org's
//     per-org role set, before and after the switch (THE PROOF), and
//     the consent page's preview agrees;
//   THE DELEGATION'S BOUNDS — the org admin manages its own org's
//     memberships (never another org's, never the org_admin role, never
//     an org_admin membership); the identity admin manages everything;
//   THE JOIN-REQUEST FLOW for an EXISTING account — the approval lands
//     the membership directly (no second account, no setup link), the
//     double-membership is the honest 409.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createRequire } from 'node:module'
import Database from 'better-sqlite3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-memberships-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The registry's bootstrap seed: one confidential client carrying the
// role-claim policy (org included — the claims proof's reader), and a
// SECOND client whose policy names 'cone' (TODO.identity-features/09 —
// the cone claim's presence proof; the first client's policy never names
// it — the absence proof, the golden's byte-clean posture).
const CLIENT = {
  client_id: 'fixture-rp',
  name: 'The membership fixture RP',
  secret: 'fixture-rp-secret',
  redirect_uris: ['http://rp.example/callback'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
const CLIENT_CONE = {
  client_id: 'fixture-rp-cone',
  name: 'The cone-gated fixture RP',
  secret: 'fixture-rp-cone-secret',
  redirect_uris: ['http://rp-cone.example/callback'],
  claims_policy: { claims: ['roles', 'groups', 'org', 'cone'] },
}
process.env.OP_CLIENT_SEED = JSON.stringify([CLIENT, CLIENT_CONE])

// The kernel package's canonical migration set (TODO.repos/01), resolved
// WITHOUT evaluating the store module — its DB path binds at import time
// and must see the env set above. createRequire resolves, never loads.
const MIGRATIONS_DIR = join(
  dirname(createRequire(import.meta.url).resolve('@oimlsmart/platform-server/package.json')),
  'migrations',
)

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let resetProfile: () => void

// ── the seeded participants register (the entity store) + the ────────
// organization registry (TODO.identity-features/05 — the identity
// service's OWN org rows, the membership graph's source of truth):
// EX1: an ACTIVE IA; 21: an ACTIVE TL; ut-nmi-nl: an ACTIVE Utilizer;
// XX1: the mid-pipeline IA — on the participants register but NEVER on
// the organization registry (the unregistered posture the gates refuse).
const ORGS = [
  { id: 'EX1', kind: 'issuing-authority', name: 'Example Issuing Authority', short_name: 'EIA', country: 'Example Member State', contact: { email: 'office@eia.example.org' } },
  { id: 'XX1', kind: 'issuing-authority', name: 'Demo Issuing Authority', short_name: 'DIA', contact: { email: 'office@dia.example.org' } },
]
const TL_ORG = { id: '21', kind: 'test-laboratory', name: 'Example Test Laboratory', short_name: 'ETL', contact: { email: 'lab@etl.example.org' } }
const UTILIZERS = [
  { id: 'ut-nmi-nl', name: 'Example Metrology Authority (Netherlands)', short_name: 'EMA-NL', country: 'Netherlands', contact: { email: 'oiml-cs@nmi.example.org' } },
]
const DECLARATIONS = [
  { id: 'decl-ia-ex1', participant_id: 'EX1', status: 'signed' },
  { id: 'decl-ia-xx1', participant_id: 'XX1', status: 'draft' },
  { id: 'decl-ut-nl', participant_id: 'ut-nmi-nl', status: 'signed' },
]

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ISSUER}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The JSON body of a request, asserting the status first. */
async function json(res: Response, status: number): Promise<any> {
  expect(res.status, `${res.url} → ${status}`).toBe(status)
  return res.json()
}

const jsonHeaders = (cookie: string) => ({ 'content-type': 'application/json', cookie })

/** The ID token's payload (the claims proof reads the values; the
 *  contract gate owns the signature's validation). */
function decodePayload(idToken: string): Record<string, unknown> {
  const part = idToken.split('.')[1]!
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf-8'))
}

/** Drive authorize → consent → decide → the code exchange; answers the
 *  ID token's claims + userinfo. THE CLAIMS PROOF's drive. The client
 *  parameterizes (the cone-gated second fixture rides the same flow). */
async function roundTrip(cookie: string, client = CLIENT): Promise<{ idToken: Record<string, unknown>; userinfo: Record<string, unknown>; consent: Record<string, unknown> }> {
  const verifier = 'membership-verifier-9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f'
  const challenge = Buffer.from(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)),
  ).toString('base64url')
  const authorize = await app.request(`${ISSUER}/op/authorize?${new URLSearchParams({
    response_type: 'code', client_id: client.client_id, redirect_uri: client.redirect_uris[0]!,
    scope: 'openid profile email', state: 'st', nonce: 'nn',
    code_challenge: challenge, code_challenge_method: 'S256',
    // The claims proof forces the consent page (TODO.identity-features/12:
    // a remembered grant would skip it on the repeat round trips).
    prompt: 'consent',
  })}`, { headers: { cookie }, redirect: 'manual' } as never)
  expect(authorize.status, 'authorize redirects to the consent page').toBe(302)
  const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!

  const consentRes = await app.request(`${ISSUER}/api/op/consent/${authId}`, { headers: { cookie } })
  const consent = await json(consentRes, 200)

  const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
    method: 'POST', headers: jsonHeaders(cookie), body: JSON.stringify({ decision: 'allow' }),
  })
  const { redirect } = await json(decide, 200)
  const code = new URL(redirect).searchParams.get('code')!

  const exchange = await app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.secret)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: client.redirect_uris[0]!,
      client_id: client.client_id, code_verifier: verifier,
    }),
  })
  const tokens = await json(exchange, 200)
  const userinfoRes = await app.request(`${ISSUER}/op/userinfo`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  })
  const userinfo = await json(userinfoRes, 200)
  return { idToken: decodePayload(tokens.id_token), userinfo, consent }
}

beforeAll(async () => {
  // The declared signing key (identity#7's posture — the round trips
  // register + validate against it).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))
  resetProfile = profileMod.resetInstanceProfileForTest

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createOpJoinRouter } = await import('../../server/routes/op-join')
  const { createOpMembershipsRouter } = await import('../../server/routes/op-memberships')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const { createUsersRouter } = await import('../../server/routes/users')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpAccountsRouter())
  root.route('/', createOpJoinRouter())
  root.route('/', createOpMembershipsRouter())
  root.route('/', createOpRegistryRouter())
  root.route('/api/users', createUsersRouter())
  app = root

  // The participants register (the entity store).
  for (const org of ORGS) await store.putEntity('organizations', org.id, null, JSON.stringify(org))
  for (const u of UTILIZERS) await store.putEntity('utilizers', u.id, null, JSON.stringify(u))
  for (const d of DECLARATIONS) await store.putEntity('participantDeclarations', d.id, null, JSON.stringify(d))

  // The organization registry (TODO.identity-features/05 — the identity
  // service's OWN rows; the membership graph's source of truth). XX1
  // stays OFF it: the mid-pipeline org is never a registry row.
  for (const org of [ORGS[0]!, TL_ORG, ...UTILIZERS.map(u => ({ ...u, kind: 'utilizer' }))]) {
    await store.createOrgRegistryOrg({
      id: org.id,
      name: org.name,
      shortName: org.short_name,
      kind: org.kind,
      country: (org as { country?: string }).country ?? null,
      contacts: org.contact?.email ? [{ name: null, email: org.contact.email }] : [],
      participantRef: org.id,
    })
  }

  // The Utilizer's org admin (the delegation's actor) — the legacy write
  // path, its membership arrives through the mirror.
  await store.createLocalUser({ email: 'admin@nmi.example.org', name: 'NL Admin', role: 'org_admin', roles: ['org_admin'], orgId: 'ut-nmi-nl' })

  // The bootstrap seeds (the demo cast + the fixture client) land on the
  // first OP request; drive one.
  const probe = await app.request(`${ISSUER}/.well-known/openid-configuration`)
  expect(probe.status).toBe(200)
  // The demo cast's seed (auth-lean's ensureInit) rides the first /api/auth call.
  await demoLogin('admin@oiml.org')
})

afterAll(() => {
  resetProfile()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

// ── the backfill + the dual-read honesty ─────────────────────────────

describe('the migration backfill (0011)', () => {
  it('creates every org-bound account\'s PRIMARY membership from the legacy columns', () => {
    // The pre-0011 state on a scratch database, then the real files.
    // The memberships FAMILY (0011's table + 0017's cone column,
    // TODO.identity-features/09) is the post-state — both stay out of
    // the pre-batch (0017's ALTER names the 0011 table).
    const scratch = new Database(':memory:')
    const files = readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort()
    for (const f of files.filter(f => !f.startsWith('0011') && !f.startsWith('0017'))) scratch.exec(readFileSync(join(MIGRATIONS_DIR, f), 'utf-8'))
    scratch.prepare("INSERT INTO users (id, email, name, provider, role, roles, org_id) VALUES ('u-ia', 'ia@x.example.org', 'IA', 'password', 'ia_officer', '[\"ia_officer\"]', 'EX1')").run()
    scratch.prepare("INSERT INTO users (id, email, name, provider, role, roles, org_id) VALUES ('u-legacy', 'legacy@x.example.org', 'Legacy', 'password', 'viewer', NULL, 'ut-nmi-nl')").run()
    scratch.prepare("INSERT INTO users (id, email, name, provider, role, roles, org_id) VALUES ('u-free', 'free@x.example.org', 'Free', 'password', 'admin', '[\"admin\"]', NULL)").run()
    scratch.exec(readFileSync(join(MIGRATIONS_DIR, '0011_org_memberships.sql'), 'utf-8'))
    const rows = scratch.prepare('SELECT user_id, org_id, roles, state, is_primary FROM org_memberships ORDER BY user_id').all() as Array<Record<string, unknown>>
    expect(rows).toEqual([
      { user_id: 'u-ia', org_id: 'EX1', roles: '["ia_officer"]', state: 'active', is_primary: 1 },
      { user_id: 'u-legacy', org_id: 'ut-nmi-nl', roles: '["viewer"]', state: 'active', is_primary: 1 },
    ])
    // 0017 (TODO.identity-features/09): the cone column lands expand-only
    // — every backfilled membership's cone is NULL (org-wide, silently).
    scratch.exec(readFileSync(join(MIGRATIONS_DIR, '0017_org_member_cones.sql'), 'utf-8'))
    const cols = scratch.prepare('PRAGMA table_info(org_memberships)').all() as Array<{ name: string }>
    expect(cols.some(c => c.name === 'cone')).toBe(true)
    const cones = scratch.prepare('SELECT cone FROM org_memberships').all() as Array<{ cone: string | null }>
    expect(cones.length).toBe(2)
    expect(cones.every(r => r.cone === null)).toBe(true)
    scratch.close()
  })

  it('the dual-read honesty: the mirrored account and the row-less account read identically', async () => {
    // The mirrored account (the demo cast's IA officer — the seed's
    // mirror/backfill wrote the row).
    const ia = await store.findUserByEmail('ia@oiml.org')
    const mirrored = await store.getOrgMembership(ia!.id, 'EX1')
    expect(mirrored).toMatchObject({ state: 'active', isPrimary: true, roles: ['ia_officer'] })

    // The row-less account: written by raw SQL AFTER the boot (the
    // pre-migration posture — the mirror never saw it).
    const { getDb } = await import('@oimlsmart/platform-server/store/sqlite')
    getDb().prepare(
      "INSERT INTO users (id, email, name, provider, role, roles, org_id) VALUES ('u-rowless', 'rowless@x.example.org', 'Rowless', 'password', 'viewer', '[\"viewer\"]', 'ut-nmi-nl')",
    ).run()
    expect(await store.getOrgMembership('u-rowless', 'ut-nmi-nl')).toBeNull()

    // The sessions read identically (the fallback answers the columns).
    const mirroredToken = await store.createSession(ia!.id)
    const rowlessToken = await store.createSession('u-rowless')
    const mirroredPayload = await store.getSessionUser(mirroredToken)
    const rowlessPayload = await store.getSessionUser(rowlessToken)
    expect(mirroredPayload).toMatchObject({ orgId: 'EX1', roles: ['ia_officer'] })
    expect(rowlessPayload).toMatchObject({ orgId: 'ut-nmi-nl', roles: ['viewer'] })
  })
})

// ── the lifecycle + the context switch + the claims proof ────────────

describe('the membership lifecycle + the active-org context', () => {
  const nlAdmin = () => demoLogin('admin@nmi.example.org')
  const officer = () => demoLogin('ia@oiml.org')

  it('the org admin invites an EXISTING account (invited); the holder accepts (active); the switch changes the claims; the disable ends the context', async () => {
    const adminCookie = await nlAdmin()
    const officerCookie = await officer()
    const officerUser = (await store.findUserByEmail('ia@oiml.org'))!

    // The invite (the org grant, its own org).
    const invite = await app.request(`${ISSUER}/api/op/org-memberships`, {
      method: 'POST', headers: jsonHeaders(adminCookie),
      body: JSON.stringify({ email: 'ia@oiml.org', roles: ['viewer'] }),
    })
    const invited = await json(invite, 201)
    expect(invited).toMatchObject({ userId: officerUser.id, orgId: 'ut-nmi-nl', roles: ['viewer'], state: 'invited' })

    // The holder's console carries the invitation.
    const accountRes = await app.request(`${ISSUER}/api/op/account`, { headers: { cookie: officerCookie } })
    const accountCtx = await json(accountRes, 200)
    const orgBlock = accountCtx.organizations
    expect(orgBlock.activeOrg).toBeNull()
    expect(orgBlock.effectiveOrg).toBe('EX1')
    expect(orgBlock.memberships.map((m: any) => [m.orgId, m.state])).toEqual([['EX1', 'active'], ['ut-nmi-nl', 'invited']])

    // An invited context refuses the switch (the honest 409).
    const early = await app.request(`${ISSUER}/api/op/account/active-org`, {
      method: 'POST', headers: jsonHeaders(officerCookie), body: JSON.stringify({ org_id: 'ut-nmi-nl' }),
    })
    expect(early.status).toBe(409)

    // The accept.
    const accept = await app.request(`${ISSUER}/api/op/account/memberships/ut-nmi-nl/accept`, {
      method: 'POST', headers: { cookie: officerCookie },
    })
    await json(accept, 200)

    // THE CLAIMS PROOF — before the switch (the primary context)…
    const before = await roundTrip(officerCookie)
    expect(before.idToken.org).toBe('EX1')
    expect(before.idToken.roles).toEqual(['ia_officer'])
    expect(before.userinfo.org).toBe('EX1')
    expect(before.userinfo.roles).toEqual(['ia_officer'])

    // …the switch…
    const switched = await app.request(`${ISSUER}/api/op/account/active-org`, {
      method: 'POST', headers: jsonHeaders(officerCookie), body: JSON.stringify({ org_id: 'ut-nmi-nl' }),
    })
    await json(switched, 200)
    // …and the session payload follows at once…
    const sessionRes = await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: officerCookie } })
    const sessionPayload = await json(sessionRes, 200)
    expect(sessionPayload.orgId).toBe('ut-nmi-nl')
    expect(sessionPayload.roles).toEqual(['viewer'])

    // …and the token carries the ACTIVE org's set (the consent preview agrees).
    const after = await roundTrip(officerCookie)
    expect(after.consent.orgClaim).toBe('ut-nmi-nl')
    expect(after.consent.roleClaims).toEqual(['viewer'])
    expect(after.idToken.org).toBe('ut-nmi-nl')
    expect(after.idToken.roles).toEqual(['viewer'])
    expect(after.userinfo.org).toBe('ut-nmi-nl')
    expect(after.userinfo.roles).toEqual(['viewer'])
    // The other membership never leaks.
    expect(JSON.stringify(after.idToken)).not.toContain('EX1')
    expect(JSON.stringify(after.idToken)).not.toContain('ia_officer')

    // The org's admin disables the membership → the session falls back to
    // the primary context, and the next token carries it (the re-judgment).
    const disable = await app.request(`${ISSUER}/api/op/org-memberships/${officerUser.id}/ut-nmi-nl/state`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({ state: 'disabled' }),
    })
    await json(disable, 200)
    const fellBack = await json(await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: officerCookie } }), 200)
    expect(fellBack.orgId).toBe('EX1')
    const afterDisable = await roundTrip(officerCookie)
    expect(afterDisable.idToken.org).toBe('EX1')
    expect(afterDisable.idToken.roles).toEqual(['ia_officer'])

    // Re-activation is deliberate; the account may switch again.
    await json(await app.request(`${ISSUER}/api/op/org-memberships/${officerUser.id}/ut-nmi-nl/state`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({ state: 'active' }),
    }), 200)
    const again = await roundTrip(officerCookie)
    expect(again.idToken.org).toBe('EX1') // the context stayed cleared until the holder switches
  })

  it('an org-free account acting as an org keeps its account-level roles in the claims (honestly)', async () => {
    // The scheme's own staff (admin, org NULL) invited into the IA as a
    // viewer: the context's set ∪ the account-level set.
    const adminCookie = await demoLogin('admin@oiml.org')
    const adminUser = (await store.findUserByEmail('admin@oiml.org'))!
    await store.createOrgMembership({ userId: adminUser.id, orgId: 'EX1', roles: ['viewer'], state: 'active', invitedBy: 'test' })
    await json(await app.request(`${ISSUER}/api/op/account/active-org`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({ org_id: 'EX1' }),
    }), 200)
    const claims = await roundTrip(adminCookie)
    expect(claims.idToken.org).toBe('EX1')
    expect(claims.idToken.roles).toEqual(['viewer', 'admin'])
    // and back to the primary (org-free) context
    await json(await app.request(`${ISSUER}/api/op/account/active-org`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({ org_id: null }),
    }), 200)
    const home = await roundTrip(adminCookie)
    expect(home.idToken.org).toBeUndefined()
    expect(home.idToken.roles).toEqual(['admin'])
    await store.deleteOrgMembership(adminUser.id, 'EX1')
  })
})

// ── the delegation's bounds ──────────────────────────────────────────

describe('the org-admin delegation is bounded', () => {
  it('the org grant manages ONLY its own org, never the org_admin role, never an org_admin membership', async () => {
    const adminCookie = await demoLogin('admin@nmi.example.org')
    const officerUser = (await store.findUserByEmail('ia@oiml.org'))!
    const nlAdminUser = (await store.findUserByEmail('admin@nmi.example.org'))!

    // Cross-org reads/writes: not found, never wider.
    const crossList = await app.request(`${ISSUER}/api/op/org-memberships?org_id=EX1`, { headers: { cookie: adminCookie } })
    expect(crossList.status).toBe(403)
    const crossEdit = await app.request(`${ISSUER}/api/op/org-memberships/${officerUser.id}/EX1/roles`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ roles: ['viewer'] }),
    })
    expect(crossEdit.status).toBe(404)

    // The org_admin role is never assignable by the org grant.
    const grantOrgAdmin = await app.request(`${ISSUER}/api/op/org-memberships/${officerUser.id}/ut-nmi-nl/roles`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ roles: ['viewer', 'org_admin'] }),
    })
    expect(grantOrgAdmin.status).toBe(403)
    expect((await grantOrgAdmin.json()).error).toContain('org_admin')

    // …and a membership HOLDING org_admin is the scheme operator's row
    // (the org grant can neither edit nor disable it — even its own).
    const ownRow = await app.request(`${ISSUER}/api/op/org-memberships/${nlAdminUser.id}/ut-nmi-nl/roles`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ roles: ['org_admin', 'viewer'] }),
    })
    expect(ownRow.status).toBe(403)
    // The state act on an org_admin-holding row: the wide grant marks a
    // second membership with org_admin first, then the org grant's
    // disable attempt on IT is refused (the self-guard never fires — the
    // target is another account's row).
    const wideCookie = await demoLogin('admin@oiml.org')
    await store.setOrgMembershipRoles(officerUser.id, 'ut-nmi-nl', ['scheme_participant', 'org_admin'])
    const toggle = await app.request(`${ISSUER}/api/op/org-memberships/${officerUser.id}/ut-nmi-nl/state`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({ state: 'disabled' }),
    })
    expect(toggle.status).toBe(403)
    expect((await toggle.json()).error).toContain('scheme operator')
    await store.setOrgMembershipRoles(officerUser.id, 'ut-nmi-nl', ['scheme_participant'])

    // The kind bounds the set: an IA-only role never lands on the Utilizer.
    const outside = await app.request(`${ISSUER}/api/op/org-memberships/${officerUser.id}/ut-nmi-nl/roles`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ roles: ['ia_officer'] }),
    })
    expect(outside.status).toBe(403)
    expect((await outside.json()).error).toContain('utilizer')

    // The honest in-bounds write stands.
    const ok = await app.request(`${ISSUER}/api/op/org-memberships/${officerUser.id}/ut-nmi-nl/roles`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ roles: ['scheme_participant'] }),
    })
    await json(ok, 200)
    expect((await store.getOrgMembership(officerUser.id, 'ut-nmi-nl'))?.roles).toEqual(['scheme_participant'])
  })

  it('the identity admin manages everything (the wide grant)', async () => {
    const wideCookie = await demoLogin('admin@oiml.org')
    const officerUser = (await store.findUserByEmail('ia@oiml.org'))!
    // The wide grant reaches any org's slice…
    const list = await app.request(`${ISSUER}/api/op/org-memberships?org_id=EX1`, { headers: { cookie: wideCookie } })
    const body = await json(list, 200)
    expect(body.grant).toBe('wide')
    expect(body.org.id).toBe('EX1')
    expect(body.members.some((m: any) => m.userId === officerUser.id && m.isPrimary)).toBe(true)
    // …and assigns org_admin on a registered org (the eligibility rule).
    const grant = await app.request(`${ISSUER}/api/op/org-memberships/${officerUser.id}/EX1/roles`, {
      method: 'PUT', headers: jsonHeaders(wideCookie), body: JSON.stringify({ roles: ['ia_officer', 'org_admin'] }),
    })
    await json(grant, 200)
    expect((await store.getOrgMembership(officerUser.id, 'EX1'))?.roles).toEqual(['ia_officer', 'org_admin'])
    // …but never on an org the registry does not carry (XX1 — the
    // mid-pipeline posture — is on the participants register only).
    const officer2 = await store.createLocalUser({ email: 'o2@x.example.org', name: 'O2', role: 'viewer', roles: ['viewer'], orgId: null })
    const ineligible = await app.request(`${ISSUER}/api/op/org-memberships`, {
      method: 'POST', headers: jsonHeaders(wideCookie), body: JSON.stringify({ email: officer2.email, org_id: 'XX1', roles: ['org_admin'] }),
    })
    expect(ineligible.status).toBe(400)
    expect((await ineligible.json()).error).toContain('not on the organization registry')
    // restore the fixture's roles for the later legs
    await store.setOrgMembershipRoles(officerUser.id, 'EX1', ['ia_officer'])
  })
})

// ── the join-request flow for an EXISTING account ────────────────────

describe('the join-request flow for an existing account', () => {
  it('the holder asks from the account console; the org admin approves; the membership lands directly (no second account)', async () => {
    const officerCookie = await demoLogin('tl@oiml.org') // the TL operator, primary org 21
    const adminCookie = await demoLogin('admin@nmi.example.org')
    const tlUser = (await store.findUserByEmail('tl@oiml.org'))!

    // The ask (the session names the account — never self-asserted fields).
    const ask = await app.request(`${ISSUER}/api/op/account/membership-requests`, {
      method: 'POST', headers: jsonHeaders(officerCookie),
      body: JSON.stringify({ org_id: 'ut-nmi-nl', requested_role: 'viewer', note: 'I run the R 60 tests for the joint review.' }),
    })
    const request = await json(ask, 201)
    expect(request).toMatchObject({ email: 'tl@oiml.org', orgId: 'ut-nmi-nl', requestedRole: 'viewer', status: 'pending' })

    // A second pending ask from the same account is the honest 409.
    const dupe = await app.request(`${ISSUER}/api/op/account/membership-requests`, {
      method: 'POST', headers: jsonHeaders(officerCookie),
      body: JSON.stringify({ org_id: 'EX1', requested_role: 'viewer' }),
    })
    expect(dupe.status).toBe(409)

    // The org's queue carries it; the approval lands the membership
    // directly (the account EXISTS — no invite, no setup link).
    const queue = await json(await app.request(`${ISSUER}/api/op/join-requests`, { headers: { cookie: adminCookie } }), 200)
    const row = queue.requests.find((r: any) => r.id === request.id)
    expect(row?.orgName).toBe('Example Metrology Authority (Netherlands)')

    const approve = await app.request(`${ISSUER}/api/op/join-requests/${request.id}/approve`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({}),
    })
    const decided = await json(approve, 200)
    expect(decided.status).toBe('approved')
    expect(decided.invite).toBeUndefined()
    expect(decided.membership).toMatchObject({ userId: tlUser.id, orgId: 'ut-nmi-nl', roles: ['viewer'], state: 'active' })
    // The membership is ACTIVE (both consents were on record) — no
    // invitation waits.
    expect((await store.getOrgMembership(tlUser.id, 'ut-nmi-nl'))?.state).toBe('active')
    // And the account list never grew a second row for the email.
    expect((await store.listUsers()).filter(u => u.email === 'tl@oiml.org').length).toBe(1)

    // Approving AGAIN (a fresh ask while the membership is active) is the
    // honest 409. The console's ask refuses a second membership ask for
    // the same org, so the re-ask rides the PUBLIC intake (the account
    // exists, the request still names the org — the queue is the decider).
    const publicAsk = await app.request(`${ISSUER}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'TL Operator', email: 'tl@oiml.org', org_id: 'ut-nmi-nl', requested_role: 'scheme_participant' }),
    })
    const request2 = await json(publicAsk, 201)
    const again = await app.request(`${ISSUER}/api/op/join-requests/${request2.id}/approve`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({}),
    })
    expect(again.status).toBe(409)
    expect((await again.json()).error).toContain('already holds an active membership')
  })
})

// ── the admin surfaces' reads ────────────────────────────────────────

describe('the registry surfaces', () => {
  it('the per-org view carries the members + the per-org roles + the org_admins + the queue', async () => {
    const wideCookie = await demoLogin('admin@oiml.org')
    const res = await app.request(`${ISSUER}/api/op/registry/orgs/ut-nmi-nl`, { headers: { cookie: wideCookie } })
    const view = await json(res, 200)
    expect(view.org).toMatchObject({ id: 'ut-nmi-nl', kind: 'utilizer', registered: true })
    const nlAdmin = (await store.findUserByEmail('admin@nmi.example.org'))!
    const officer = (await store.findUserByEmail('ia@oiml.org'))!
    expect(view.members.some((m: any) => m.userId === nlAdmin.id && m.roles.includes('org_admin'))).toBe(true)
    expect(view.members.some((m: any) => m.userId === officer.id && m.orgId === 'ut-nmi-nl')).toBe(true)
    expect(view.requests.some((r: any) => r.email === 'tl@oiml.org')).toBe(true)
    // The gate: the org admin's grant never reads the registry's per-org view.
    const orgAdminCookie = await demoLogin('admin@nmi.example.org')
    const refused = await app.request(`${ISSUER}/api/op/registry/orgs/ut-nmi-nl`, { headers: { cookie: orgAdminCookie } })
    expect(refused.status).toBe(403)
    // An unknown org is the honest 404.
    const missing = await app.request(`${ISSUER}/api/op/registry/orgs/no-such-org`, { headers: { cookie: wideCookie } })
    expect(missing.status).toBe(404)
  })

  it('the per-user detail aggregate carries the memberships', async () => {
    const wideCookie = await demoLogin('admin@oiml.org')
    const officer = (await store.findUserByEmail('ia@oiml.org'))!
    const res = await app.request(`${ISSUER}/api/op/registry/users/${officer.id}`, { headers: { cookie: wideCookie } })
    const detail = await json(res, 200)
    const byOrg = new Map((detail.memberships as any[]).map(m => [m.orgId, m]))
    expect(byOrg.get('EX1')).toMatchObject({ state: 'active', isPrimary: true, roles: ['ia_officer'] })
    expect(byOrg.get('ut-nmi-nl')).toMatchObject({ state: 'active', isPrimary: false, orgName: 'Example Metrology Authority (Netherlands)' })
  })
})

// ── the member data cone (TODO.identity-features/09, wave A) ─────────

describe('the org-member cone', () => {
  it('the org admin sets the cone; the claims carry it for the cone-gated client ONLY; the audit slice records every act', async () => {
    const adminCookie = await demoLogin('admin@nmi.example.org')
    const officerCookie = await demoLogin('ia@oiml.org')
    const officer = (await store.findUserByEmail('ia@oiml.org'))!
    const nlAdmin = (await store.findUserByEmail('admin@nmi.example.org'))!

    // The member's posture starts org-wide (NULL — the silent default).
    const listed = await json(await app.request(`${ISSUER}/api/op/org-memberships?org_id=ut-nmi-nl`, { headers: { cookie: adminCookie } }), 200)
    const row = (listed.members as any[]).find(m => m.userId === officer.id && m.orgId === 'ut-nmi-nl')
    expect(row.cone).toEqual({ scope: 'org-wide', readOnly: false })

    // The cone act (the org grant, its own org)…
    const set = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/cone`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ cone: 'assigned' }),
    })
    const narrowed = await json(set, 200)
    expect(narrowed.cone).toEqual({ scope: 'assigned', readOnly: false })
    expect(narrowed.roles).toEqual(row.roles) // the cone NEVER touches the role set

    // …the switch into the org, then THE CLAIMS: the cone-gated client
    // learns the posture; the plain client never does.
    await json(await app.request(`${ISSUER}/api/op/account/active-org`, {
      method: 'POST', headers: jsonHeaders(officerCookie), body: JSON.stringify({ org_id: 'ut-nmi-nl' }),
    }), 200)
    const gated = await roundTrip(officerCookie, CLIENT_CONE)
    expect(gated.idToken.org).toBe('ut-nmi-nl')
    expect(gated.idToken.cone).toBe('assigned')
    expect(gated.userinfo.cone).toBe('assigned')
    const plain = await roundTrip(officerCookie, CLIENT)
    expect(plain.idToken.cone).toBeUndefined()
    expect(plain.userinfo.cone).toBeUndefined()

    // The orthogonal read-only modifier composes.
    await json(await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/cone`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ cone: 'assigned+read-only' }),
    }), 200)
    const composed = await roundTrip(officerCookie, CLIENT_CONE)
    expect(composed.idToken.cone).toBe('assigned+read-only')

    // Back to org-wide — the column clears (the claim says the default).
    await json(await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/cone`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ cone: 'org-wide' }),
    }), 200)
    expect((await store.getOrgMembership(officer.id, 'ut-nmi-nl'))?.cone).toEqual({ scope: 'org-wide', readOnly: false })
    const restored = await roundTrip(officerCookie, CLIENT_CONE)
    expect(restored.idToken.cone).toBe('org-wide')

    // The audit slice records EVERY act, with the postures named.
    const activityRes = await app.request(`${ISSUER}/api/op/org-memberships/activity?org_id=ut-nmi-nl`, { headers: { cookie: adminCookie } })
    const activity = await json(activityRes, 200)
    const coneActs = (activity.activity as any[]).filter(e => e.action === 'membership.cone' && e.entity_id === officer.id)
    expect(coneActs.length).toBe(3)
    expect(coneActs[0]).toMatchObject({ user_id: nlAdmin.id, metadata: { cone: 'org-wide', previous: 'assigned+read-only' } })

    // The bounds: a member WITHOUT the grant never sets a cone…
    const noGrant = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/cone`, {
      method: 'PUT', headers: jsonHeaders(officerCookie), body: JSON.stringify({ cone: 'assigned' }),
    })
    expect(noGrant.status).toBe(403)
    // …the org grant never reaches another org's row (not found, never wider)…
    const crossOrg = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/EX1/cone`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ cone: 'assigned' }),
    })
    expect(crossOrg.status).toBe(404)
    // …never touches an org_admin membership…
    const adminRow = await app.request(`${ISSUER}/api/op/org-memberships/${nlAdmin.id}/ut-nmi-nl/cone`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ cone: 'read-only' }),
    })
    expect(adminRow.status).toBe(403)
    // …and junk is the honest 400 (the store-side fail-closed parse is
    // the backstop; the route refuses to WRITE it).
    const junk = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/cone`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ cone: 'everything' }),
    })
    expect(junk.status).toBe(400)

    // The audit slice's gate: the grantless member gets the honest 403;
    // the org admin's slice never widens to another org.
    const refused = await app.request(`${ISSUER}/api/op/org-memberships/activity?org_id=ut-nmi-nl`, { headers: { cookie: officerCookie } })
    expect(refused.status).toBe(403)
    const widened = await app.request(`${ISSUER}/api/op/org-memberships/activity?org_id=EX1`, { headers: { cookie: adminCookie } })
    expect(widened.status).toBe(403)

    // The identity admin's per-org view carries the cone honestly.
    const wideCookie = await demoLogin('admin@oiml.org')
    const view = await json(await app.request(`${ISSUER}/api/op/registry/orgs/ut-nmi-nl`, { headers: { cookie: wideCookie } }), 200)
    const viewRow = (view.members as any[]).find(m => m.userId === officer.id && m.orgId === 'ut-nmi-nl')
    expect(viewRow.cone).toEqual({ scope: 'org-wide', readOnly: false })

    // Leave the fixture as found (the primary context).
    await json(await app.request(`${ISSUER}/api/op/account/active-org`, {
      method: 'POST', headers: jsonHeaders(officerCookie), body: JSON.stringify({ org_id: null }),
    }), 200)
  })
})

// ── the effective-permission explainer (TODO.identity-features/09, wave B)

describe('the effective-permission explainer (the org-scoped endpoint)', () => {
  it('the org grant reads the member’s COMPUTED effective set — the roles, the permissions, the cone’s effect, the dry-run', async () => {
    const adminCookie = await demoLogin('admin@nmi.example.org')
    const officer = (await store.findUserByEmail('ia@oiml.org'))!
    const nlAdmin = (await store.findUserByEmail('admin@nmi.example.org'))!

    // The gates: unauthenticated is the honest 401; a member WITHOUT the
    // grant never explains (their own row included); the org grant never
    // reaches another org's row (not found, never wider).
    const anon = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/explain`)
    expect(anon.status).toBe(401)
    const officerCookie = await demoLogin('ia@oiml.org')
    const noGrant = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/explain`, { headers: { cookie: officerCookie } })
    expect(noGrant.status).toBe(403)
    const crossOrg = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/EX1/explain`, { headers: { cookie: adminCookie } })
    expect(crossOrg.status).toBe(404)
    const noRow = await app.request(`${ISSUER}/api/op/org-memberships/no-such-user/ut-nmi-nl/explain`, { headers: { cookie: adminCookie } })
    expect(noRow.status).toBe(404)

    // The member (the officer acting as the Utilizer, scheme_participant,
    // org-wide): the computed set, every piece composed.
    const res = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/explain`, { headers: { cookie: adminCookie } })
    const x = await json(res, 200)
    expect(x.member).toMatchObject({ userId: officer.id, email: 'ia@oiml.org', state: 'active', accountActive: true })
    expect(x.org).toMatchObject({ id: 'ut-nmi-nl', kind: 'utilizer' })
    expect(x.acting).toBe(true)
    expect(x.context).toMatchObject({ orgId: 'ut-nmi-nl', cone: { scope: 'org-wide', readOnly: false } })
    expect(x.roles).toEqual([
      { id: 'scheme_participant', source: 'membership', known: true, permissions: [{ id: 'anr.declare', label: expect.any(String) }] },
    ])
    expect(x.permissions).toEqual([
      { id: 'anr.declare', label: expect.any(String), fromRoles: ['scheme_participant'], effective: true, effect: 'held' },
    ])
    expect(x.kindBound).toMatchObject({ orgAdminRow: false, outside: [] })
    expect(x.visibility.orgBound).toBe(true) // the account's primary is the IA desk
    const classes = new Map((x.visibility.classes as any[]).map(c => [c.store, c]))
    expect(classes.get('applications').ownOrg).toMatchObject({ visible: true, reason: 'org-field' })
    expect(classes.get('applications').foreignOrg).toMatchObject({ visible: false, reason: 'org-field-miss' })
    expect(classes.get('measuringInstrumentModels').ownOrg).toMatchObject({ visible: true, reason: 'catalog' })

    // The cone moves (the wave-A act) — the explainer reports exactly the
    // narrowed reality the gates enforce.
    await json(await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/cone`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ cone: 'assigned+read-only' }),
    }), 200)
    const narrowedRes = await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/explain`, { headers: { cookie: adminCookie } })
    const narrowed = await json(narrowedRes, 200)
    expect(narrowed.cone).toEqual({
      posture: 'assigned+read-only',
      read: { scope: 'assigned', effect: 'named-rows-only' },
      write: { refused: true, effect: 'read-only-refused' },
    })
    expect(narrowed.permissions[0]).toMatchObject({ id: 'anr.declare', effective: false, effect: 'read-only-refused' })
    const narrowedClasses = new Map((narrowed.visibility.classes as any[]).map(c => [c.store, c]))
    expect(narrowedClasses.get('testRuns').ownOrg).toMatchObject({ visible: false, reason: 'assigned-miss' })
    expect(narrowedClasses.get('testRuns').named).toMatchObject({ visible: true, reason: 'assigned-hit' })
    expect(narrowedClasses.get('applications').ownOrg).toMatchObject({ visible: false, reason: 'assigned-no-key' })
    await json(await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/cone`, {
      method: 'PUT', headers: jsonHeaders(adminCookie), body: JSON.stringify({ cone: 'org-wide' }),
    }), 200)

    // The org_admin ROW explains too (the read is no wider than the
    // people list that already shows it; the refusal on the mutation
    // routes guards acts, never this read).
    const adminRow = await json(await app.request(`${ISSUER}/api/op/org-memberships/${nlAdmin.id}/ut-nmi-nl/explain`, { headers: { cookie: adminCookie } }), 200)
    expect(adminRow.kindBound.orgAdminRow).toBe(true)
    expect(adminRow.permissions.map((p: any) => p.id)).toEqual(['org.users.manage'])
    expect(adminRow.visibility.orgBound).toBe(false) // org_admin is not an org-scoped role — the read gate never narrows it

    // The identity admin (the wide grant) explains any org's member —
    // here the officer's PRIMARY context (the IA's desk set).
    const wideCookie = await demoLogin('admin@oiml.org')
    const wide = await json(await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/EX1/explain`, { headers: { cookie: wideCookie } }), 200)
    expect(wide.context.orgId).toBe('EX1')
    expect(wide.roles.map((r: any) => r.id)).toEqual(['ia_officer'])
    expect(wide.permissions.map((p: any) => p.id)).toContain('certificate.issue')

    // The state honesty: a disabled membership acts as nothing — the
    // explainer answers the empty set, never another context's posture.
    await json(await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/state`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({ state: 'disabled' }),
    }), 200)
    const inactive = await json(await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/explain`, { headers: { cookie: adminCookie } }), 200)
    expect(inactive.acting).toBe(false)
    expect(inactive.stateNote).toBe('membership-disabled')
    expect(inactive.roles).toEqual([])
    expect(inactive.permissions).toEqual([])
    await json(await app.request(`${ISSUER}/api/op/org-memberships/${officer.id}/ut-nmi-nl/state`, {
      method: 'POST', headers: jsonHeaders(adminCookie), body: JSON.stringify({ state: 'active' }),
    }), 200)
  })
})
