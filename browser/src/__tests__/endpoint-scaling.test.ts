// ─────────────────────────────────────────────────────────────────────
// THE ENDPOINT-SCALING GATE (docs/deployment/endpoint-scaling.md — the
// N+1 doctrine), the identity service's half. Every root-level GET list
// endpoint of the OP runs against a small fixture AND the same fixture
// grown 10×, with the store seam wrapped in the counting facade
// (endpoint-scaling.ts): the store-call count must be IDENTICAL at both
// scales (an O(1) endpoint) or within the leg's DECLARED per-row budget
// (a named residual, never a hiding place).
//
// The disease this gates: a handler awaiting a store read PER ROW — the
// production registry import made the admin orgs page a measured 2–11 s
// answer (217 sequential store round trips), and the platform sibling's
// 2026-09 portal load audit measured the same class at 107 s on a
// 423-row store. The fix pattern: prefetch the referenced sets ONCE per
// request, group in memory, never await per row.
//
// The legs named coveredBy belong to a sibling wave's file
// (routes/op-registry.ts — fix/registry-orgs-n1): the gate asserts their
// correct end state — red until that wave lands, green after. That is
// the gate working, not a defect of it.
//
// Conventions: the house's in-process pattern (id-registry.test.ts) —
// one temp SQLite DB, the REAL routers mounted on a Hono app, the demo
// cast for the admin session; fixtures land through the store seam
// directly (setup is never measured). Each leg is self-contained: seed
// small → warm → measure → grow 10× → measure → assert the delta.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-id-endpoint-scaling-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

import { installStore, type ServerStore } from '@oimlsmart/platform-server/store'
import { StoreCallCounter, expectScalingInvariant, type StoreCallReport } from './endpoint-scaling'

const SMALL = 3
const LARGE = 30

let app: import('hono').Hono
let store: ServerStore
const counter = new StoreCallCounter()

let adminCookie: string
let memberCookie: string
let memberId: string

function req(path: string, cookie?: string): Request {
  const headers = new Headers()
  if (cookie) headers.set('cookie', cookie)
  return new Request(`${ISSUER}${path}`, { headers })
}

interface MeasuredLeg { small: StoreCallReport; large: StoreCallReport; smallRows: number; largeRows: number }

/** One leg's full run: seed the small fixture, warm the endpoint (the
 *  first-touch ensures are one-time costs, never the disease), measure,
 *  grow the fixture 10×, measure again. */
async function runLeg(opts: {
  seedSmall: () => Promise<number> | number
  grow: () => Promise<number> | number
  request: () => Promise<Response> | Response
  expectStatus?: number
}): Promise<MeasuredLeg> {
  const smallRows = await opts.seedSmall()
  const expected = opts.expectStatus ?? 200
  const warm = await opts.request()
  expect(warm.status, `the leg's warm-up request answers ${expected}`).toBe(expected)
  const small = await counter.measure(() => opts.request())
  expect(small.result.status, `the leg's small-scale request answers ${expected}`).toBe(expected)
  const largeRows = await opts.grow()
  const large = await counter.measure(() => opts.request())
  expect(large.result.status, `the leg's large-scale request answers ${expected}`).toBe(expected)
  return { small: small.report, large: large.report, smallRows, largeRows }
}

// ── the fixtures (id-prefixed 'gate-', store-direct, never measured) ──

/** N more OP password accounts (provider 'password' — the accounts
 *  list's + the dashboard overview's sign-in-posture legs). */
async function seedOpAccounts(from: number, count: number): Promise<void> {
  for (let i = from; i < from + count; i++) {
    await store.createOpAccount({
      email: `gate-account-${i}@example.org`, name: `Gate Account ${i}`, role: 'viewer',
    })
  }
}

/** N more registry organizations. */
async function seedRegistryOrgs(from: number, count: number): Promise<void> {
  for (let i = from; i < from + count; i++) {
    await store.createOrgRegistryOrg({
      id: `gate-org-${i}`, name: `Gate Organization ${i}`, shortName: `GO-${i}`,
      kind: 'manufacturer', country: 'NL', contacts: [],
    })
  }
}

/** N more members of the fixture org (one account + one membership
 *  each — the org console's people slice). */
async function seedMembers(from: number, count: number): Promise<void> {
  for (let i = from; i < from + count; i++) {
    const account = await store.createOpAccount({
      email: `gate-member-${i}@example.org`, name: `Gate Member ${i}`, role: 'viewer',
    })
    await store.createOrgMembership({
      userId: account!.id, orgId: 'gate-org', roles: [], state: 'active', invitedBy: 'gate@example.org',
    })
  }
}

/** N more OIDC clients carrying LAUNCH cards in the 'request' posture
 *  (the home feed's + the token services' per-client legs). */
async function seedLaunchClients(from: number, count: number): Promise<void> {
  for (let i = from; i < from + count; i++) {
    const clientId = `gate-client-${i}`
    await store.upsertOidcClient({
      clientId, name: `Gate Service ${i}`, secretHash: 'gate-hash',
      redirectUris: ['https://service.example/callback'], claimsPolicy: null,
    })
    await store.setOidcClientLaunch(clientId, {
      url: 'https://service.example/', icon: null, description: null, visibility: 'request',
    })
  }
}

/** N more consent grants for the member account, one per fixture client
 *  (the grants list's per-row client lookup). Runs after the clients
 *  leg — its clients exist by then. */
async function seedGrants(from: number, count: number): Promise<void> {
  for (let i = from; i < from + count; i++) {
    await store.recordConsentGrant({ userId: memberId, clientId: `gate-client-${i}`, scope: 'openid profile' })
  }
}

/** N more upstream identity links on the member account. */
async function seedLinks(from: number, count: number): Promise<void> {
  for (let i = from; i < from + count; i++) {
    await store.createIdentityLink({
      userId: memberId, provider: `gate-idp-${i}`, providerAccountId: `gate-sub-${i}`, linkedBy: 'gate@example.org',
    })
  }
}

/** N more join requests against the fixture org. */
async function seedJoinRequests(from: number, count: number): Promise<void> {
  for (let i = from; i < from + count; i++) {
    await store.createOrgJoinRequest({
      name: `Gate Joiner ${i}`, email: `gate-joiner-${i}@example.org`,
      orgId: 'gate-org', orgNameText: null, requestedRole: 'member', note: null,
    })
  }
}

/** N more live sessions (the dashboard's live-sessions list) — the
 *  holder account is created once (the store's createOpAccount refuses
 *  the duplicate honestly). */
let sessionHolderId: string | null = null
async function seedSessions(from: number, count: number): Promise<void> {
  if (!sessionHolderId) {
    const account = await store.createOpAccount({
      email: 'gate-session-holder@example.org', name: 'Gate Session Holder', role: 'viewer',
    })
    sessionHolderId = account!.id
  }
  for (let i = from; i < from + count; i++) {
    await store.createSession(sessionHolderId)
  }
}

/** N more audit events on the member account (the account/console audit
 *  slices + the dashboard's journal reads). */
async function seedAuditEvents(from: number, count: number): Promise<void> {
  for (let i = from; i < from + count; i++) {
    await store.putEntity('auditEvents', `gate-aud-${i}`, null, JSON.stringify({
      id: `gate-aud-${i}`, timestamp: `2026-08-${String((i % 28) + 1).padStart(2, '0')}T00:00:00.000Z`,
      entity_type: 'account', entity_id: memberId, action: 'account.gate_probe',
      user_id: memberId, user_name: 'Gate Member', metadata: {},
    }))
  }
}

beforeAll(async () => {
  // The declared signing key (the id-registry posture: a simulated
  // deployment never registers a generated key silently).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const sqlite = await import('@oimlsmart/platform-server/store/sqlite')
  // The counting facade goes on the seam BEFORE any router is built —
  // every handler's getStore() rides the counter from the first request.
  store = counter.wrap(sqlite.installSqliteStore())
  installStore(store)
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

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createOpFactorsRouter } = await import('../../server/routes/op-factors')
  const { createOpTokensRouter } = await import('../../server/routes/op-tokens')
  const { createOpGrantsRouter } = await import('../../server/routes/op-grants')
  const { createOpJoinRouter } = await import('../../server/routes/op-join')
  const { createOpMembershipsRouter } = await import('../../server/routes/op-memberships')
  const { createOpKeysRouter } = await import('../../server/routes/op-keys')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const { createOpDashboardRouter } = await import('../../server/routes/op-dashboard')
  const { createOpHomeRouter } = await import('../../server/routes/op-home')
  const { createOpWhoamiRouter } = await import('../../server/routes/op-whoami')
  const { createOpUpstreamRouter } = await import('../../server/routes/op-upstream')
  const { createUsersRouter } = await import('../../server/routes/users')
  app = new Hono()
  app.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  app.route('/', createOpRouter())
  app.route('/', createOpUpstreamRouter())
  app.route('/', createOpAccountsRouter())
  app.route('/', createOpFactorsRouter())
  app.route('/', createOpTokensRouter())
  app.route('/', createOpGrantsRouter())
  app.route('/', createOpJoinRouter())
  app.route('/', createOpMembershipsRouter())
  app.route('/', createOpKeysRouter())
  app.route('/', createOpRegistryRouter())
  app.route('/', createOpDashboardRouter())
  app.route('/', createOpHomeRouter())
  app.route('/', createOpWhoamiRouter())
  app.route('/api/users', createUsersRouter())

  // The bootstrap probes land the seeds (the client registry, the demo
  // cast) before any measurement.
  await app.request(`${ISSUER}/.well-known/openid-configuration`)
  const login = await app.request(`${ISSUER}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
  })
  expect(login.ok, 'the admin demo login stands').toBe(true)
  adminCookie = login.headers.get('set-cookie')!.split(';')[0]!

  // The member account the account-scoped legs ride (the console's own
  // posture: a plain account with an org membership).
  const member = await store.createOpAccount({
    email: 'gate-member@example.org', name: 'Gate Member', role: 'viewer',
  })
  memberId = member!.id
  memberCookie = `oiml-session=${await store.createSession(memberId)}`

  // The fixture org (the memberships/join-requests/registry legs' home).
  await store.createOrgRegistryOrg({
    id: 'gate-org', name: 'Gate Organization', shortName: 'GO',
    kind: 'manufacturer', country: 'NL', contacts: [],
  })
// The 120 s hook budget: the full-suite parallel load's boot-timeout
// flake class (the platform sibling's vitest.config.ts documents it) is
// a beforeAll TIMEOUT, never semantic — this boot mounts 14 routers; the
// headroom is the honest answer, the gate's own runs take seconds.
}, 120_000)

// ═══════════════════════════════════════════════════════════════════
// The legs. Declaration order is load-bearing where a fixture names
// another leg's rows (named in the leg's comment); every other leg is
// self-contained (the delta assertion makes the foreign rows cancel).
// ═══════════════════════════════════════════════════════════════════

describe('the admin consoles — the fixed N+1s', () => {
  it('GET /api/op/accounts (the registry list: the per-row posture reads, batched where the seam carries one)', async () => {
    // After the fix: the per-client assignments load ONCE
    // (listAllOpClientRoles, grouped in memory). The residual — the
    // sign-in posture + the linked handles, two reads per row, run
    // CONCURRENTLY — awaits the kernel's bulk sign-in-posture read (the
    // named follow-up; the seam carries no bulk variant for them).
    const leg = await runLeg({
      seedSmall: () => seedOpAccounts(0, SMALL).then(() => SMALL),
      grow: () => seedOpAccounts(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/accounts', adminCookie)),
    })
    expectScalingInvariant({
      label: 'GET /api/op/accounts as admin', ...leg,
      budgetPerRow: 2,
      budgetNote: 'the sign-in posture (countSignInMethods) + the linked handles (listIdentityLinks) have no bulk read on the kernel seam — the kernel bulk-posture follow-up drives this to 0; the per-client assignments ARE batched (listAllOpClientRoles)',
    })
  })

  it('GET /api/op/dashboard/overview (the invited-count residual, budgeted)', async () => {
    // The invited count reads each active password account's posture —
    // the same missing bulk seam as the accounts list. ONE read per
    // added password account, never more.
    const seed = async (from: number, count: number) => {
      for (let i = from; i < from + count; i++) {
        await store.createOpAccount({
          email: `gate-overview-${i}@example.org`, name: `Gate Overview ${i}`, role: 'viewer',
        })
      }
    }
    const leg = await runLeg({
      seedSmall: () => seed(0, SMALL).then(() => SMALL),
      grow: () => seed(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/dashboard/overview', adminCookie)),
    })
    expectScalingInvariant({
      label: 'GET /api/op/dashboard/overview as admin', ...leg,
      budgetPerRow: 1,
      budgetNote: 'the invited count reads countSignInMethods per active password account — no bulk variant on the kernel seam; the kernel bulk-posture follow-up drives this to 0',
    })
  })

  it('GET /api/op/org-memberships (the people slice’s per-member account scans, hoisted)', async () => {
    const leg = await runLeg({
      seedSmall: () => seedMembers(0, SMALL).then(() => SMALL),
      grow: () => seedMembers(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/org-memberships?org_id=gate-org', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/org-memberships as admin', ...leg })
    // The content pin: every member lands, the account join resolved.
    const body = await (await app.fetch(req('/api/op/org-memberships?org_id=gate-org', adminCookie))).json() as { members: Array<{ email: string | null }> }
    expect(body.members.filter(m => m.email?.startsWith('gate-member-')).length).toBe(LARGE)
  })
})

describe('the account consoles — the fixed N+1s', () => {
  it('GET /api/op/home (the launcher feed’s per-client role reads, batched)', async () => {
    const leg = await runLeg({
      seedSmall: () => seedLaunchClients(0, SMALL).then(() => SMALL),
      grow: () => seedLaunchClients(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/home', memberCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/home as member', ...leg })
    // The content pin: every request-posture card renders.
    const body = await (await app.fetch(req('/api/op/home', memberCookie))).json() as { services: Array<{ clientId: string; state: string }> }
    expect(body.services.filter(s => s.clientId.startsWith('gate-client-')).length).toBe(LARGE)
  })

  it('GET /api/op/account/tokens (the services catalog’s per-client reads, batched)', async () => {
    // After the home leg: gate-client-0..29 exist. This leg's own growth
    // extends the same generation.
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => seedLaunchClients(LARGE, LARGE - SMALL).then(() => LARGE + (LARGE - SMALL)),
      request: () => app.fetch(req('/api/op/account/tokens', memberCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/account/tokens as member', ...leg, smallRows: LARGE })
  })

  it('GET /api/op/account/grants (the per-grant client lookup, prefetched)', async () => {
    const leg = await runLeg({
      seedSmall: () => seedGrants(0, SMALL).then(() => SMALL),
      grow: () => seedGrants(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/account/grants', memberCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/account/grants as member', ...leg })
    // The content pin: the grant names resolve from the prefetched
    // registry exactly as the per-row lookups answered them.
    const body = await (await app.fetch(req('/api/op/account/grants', memberCookie))).json() as { grants: Array<{ clientId: string; clientName: string }> }
    const gateGrants = body.grants.filter(g => g.clientId.startsWith('gate-client-'))
    expect(gateGrants.length).toBe(LARGE)
    expect(gateGrants.every(g => g.clientName === `Gate Service ${g.clientId.split('-').pop()}`)).toBe(true)
  })
})

describe('the registry surface — covered by the sibling wave (fix/registry-orgs-n1)', () => {
  it('GET /api/op/registry/orgs (the per-org membership reads)', async () => {
    // The sibling wave's fix (the kernel's listAllOrgMemberships, grouped
    // in memory) is the asserted end state — RED until it lands.
    const leg = await runLeg({
      seedSmall: () => seedRegistryOrgs(0, SMALL).then(() => SMALL),
      grow: () => seedRegistryOrgs(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/registry/orgs', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/registry/orgs as admin', ...leg })
  })

  it('GET /api/op/registry/users (the ceiling pin on the per-row posture reads)', async () => {
    // The sibling wave parallelizes these reads; the kernel seam carries
    // no bulk variant, so the count's residual is 2 per row — pinned
    // here as the CEILING (a regression beyond it fails), with the
    // kernel bulk-posture follow-up named to drive it to 0.
    const seed = async (from: number, count: number) => {
      for (let i = from; i < from + count; i++) {
        await store.createOpAccount({
          email: `gate-registry-user-${i}@example.org`, name: `Gate Registry User ${i}`, role: 'viewer',
        })
      }
    }
    const leg = await runLeg({
      seedSmall: () => seed(0, SMALL).then(() => SMALL),
      grow: () => seed(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/registry/users', adminCookie)),
    })
    expectScalingInvariant({
      label: 'GET /api/op/registry/users as admin', ...leg,
      budgetPerRow: 2,
      budgetNote: 'the sign-in posture + the linked handles have no bulk read on the kernel seam (the sibling wave runs them concurrently — the count stands); the kernel bulk-posture follow-up drives this to 0',
    })
  })
})

describe('the pinned constants (the regression net)', () => {
  it('GET /api/op/registry/activity (the registry’s audit slice)', async () => {
    const leg = await runLeg({
      seedSmall: () => seedAuditEvents(0, SMALL).then(() => SMALL),
      grow: () => seedAuditEvents(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/registry/activity', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/registry/activity as admin', ...leg })
  })

  it('GET /api/op/registry/users/:id/activity (one account’s trail)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req(`/api/op/registry/users/${memberId}/activity`, adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/registry/users/:id/activity as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/registry/users/:id (the account detail’s fixed aggregate)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req(`/api/op/registry/users/${memberId}`, adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/registry/users/:id as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/registry/orgs/:orgId (the org detail’s fixed aggregate)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/registry/orgs/gate-org', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/registry/orgs/:orgId as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/dashboard/sessions (the live-sessions aggregate)', async () => {
    const leg = await runLeg({
      seedSmall: () => seedSessions(0, SMALL).then(() => SMALL),
      grow: () => seedSessions(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/dashboard/sessions', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/dashboard/sessions as admin', ...leg })
  })

  it('GET /api/op/dashboard/audit (the journal’s single read)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/dashboard/audit', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/dashboard/audit as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/dashboard/security (the journal’s signals, one read)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/dashboard/security', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/dashboard/security as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/dashboard/clients (the per-client activity over one journal read)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/dashboard/clients', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/dashboard/clients as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/dashboard/access-review (the quarterly review’s live read — batched by construction)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/dashboard/access-review', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/dashboard/access-review as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/join-requests (the decision queues)', async () => {
    const leg = await runLeg({
      seedSmall: () => seedJoinRequests(0, SMALL).then(() => SMALL),
      grow: () => seedJoinRequests(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/join-requests', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/join-requests as admin', ...leg })
  })

  it('GET /api/op/organizations (the join page’s public selector)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/organizations')),
    })
    expectScalingInvariant({ label: 'GET /api/op/organizations (public)', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/providers (the upstream registry)', async () => {
    const seed = async (from: number, count: number) => {
      for (let i = from; i < from + count; i++) {
        await store.upsertIdentityProvider({
          id: `gate-idp-${i}`, kind: 'oidc', displayName: `Gate IdP ${i}`,
          issuer: `https://idp-${i}.example`, clientId: `gate-client-${i}`,
          clientSecretRef: 'GATE_SECRET', enabled: i % 2 === 0,
        })
      }
    }
    const leg = await runLeg({
      seedSmall: () => seed(0, SMALL).then(() => SMALL),
      grow: () => seed(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/providers', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/providers as admin', ...leg })
  })

  it('GET /api/op/providers/public (the login page’s buttons)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/providers/public')),
    })
    expectScalingInvariant({ label: 'GET /api/op/providers/public (public)', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/account/links (the member’s linked identities)', async () => {
    const leg = await runLeg({
      seedSmall: () => seedLinks(0, SMALL).then(() => SMALL),
      grow: () => seedLinks(SMALL, LARGE - SMALL).then(() => LARGE),
      request: () => app.fetch(req('/api/op/account/links', memberCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/account/links as member', ...leg })
  })

  it('GET /api/op/account/factors (the member’s factors aggregate)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/account/factors', memberCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/account/factors as member', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/account/activity (the member’s own audit slice)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/account/activity', memberCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/account/activity as member', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/clients (the client registry)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/clients', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/clients as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/users (the instance’s account slice)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/users', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/users as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/users/org-admin-state (the per-org administration state)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/users/org-admin-state', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/users/org-admin-state as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/org-memberships/activity (the org’s audit slice)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/org-memberships/activity?org_id=gate-org', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/org-memberships/activity as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/op/org-keys/:orgId (the org’s key custody chain)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/op/org-keys/gate-org', adminCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/op/org-keys/:orgId as admin', ...leg, largeRows: SMALL })
  })

  it('GET /api/auth/demo-accounts (the login cast)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/auth/demo-accounts')),
    })
    expectScalingInvariant({ label: 'GET /api/auth/demo-accounts (public)', ...leg, largeRows: SMALL })
  })

  it('GET /api/auth/session (the session resolution itself)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/api/auth/session', memberCookie)),
    })
    expectScalingInvariant({ label: 'GET /api/auth/session as member', ...leg, largeRows: SMALL })
  })

  it('GET /op/whoami (the account’s own projection)', async () => {
    const leg = await runLeg({
      seedSmall: () => SMALL,
      grow: () => SMALL,
      request: () => app.fetch(req('/op/whoami', memberCookie)),
    })
    expectScalingInvariant({ label: 'GET /op/whoami as member', ...leg, largeRows: SMALL })
  })
})
