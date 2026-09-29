// ─────────────────────────────────────────────────────────────────────
// TODO.modern/05 — SCIM 2.0 provisioning (RFC 7644), in-process: the
// config-gated surface (SCIM_BEARER_TOKEN unset = /scim answers 404,
// the surface does not exist), the Users lifecycle (create → the
// invited account + the enrollment token; the userName filter subset;
// pagination; the honest disable that kills sessions; delete =
// deactivate never erase), and the RFC's error taxonomy. The REAL app
// factory + the REAL store.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-scim-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
const BEARER = 'scim-bearer-probe'
process.env.SCIM_BEARER_TOKEN = BEARER

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>

const authed = (init: RequestInit = {}): RequestInit => ({
  ...init,
  headers: { ...(init.headers ?? {}), authorization: `Bearer ${BEARER}` },
})

interface ScimUser {
  id: string
  userName: string
  active: boolean
  name?: { formatted?: string; givenName?: string; familyName?: string }
}

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: true, instanceProfile: profileMod.getInstanceProfile() })
  store = (await import('../../server/store')).getStore()
})

afterEach(() => {
  process.env.SCIM_BEARER_TOKEN = BEARER
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
  delete process.env.SCIM_BEARER_TOKEN
})

describe('Groups (TODO.sota/03, RFC 7644 §4.2)', () => {
  let authorId: string
  let reviewerId: string

  beforeAll(async () => {
    // The demo cast seeds LAZILY (the first credential-gated request)
    // — prime it through the demo login, then resolve the member ids.
    await app.request('/api/auth/demo', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oimlsmart.org', password: 'demo2026' }),
    })
    const users = await store.listUsers()
    authorId = users.find(u => u.email.includes('ia@'))?.id ?? users[0]!.id
    reviewerId = users.find(u => u.email.includes('tl@') || u.email.includes('viewer@'))?.id ?? users[1]!.id
  })

  it('the empty list answers the ListResponse shape', async () => {
    const res = await app.request('/scim/v2/Groups', authed())
    expect(res.status).toBe(200)
    const body = await res.json() as { totalResults: number; Resources: unknown[] }
    expect(body.totalResults).toBe(0)
    expect(body.Resources).toEqual([])
  })

  it('CREATE: the group with members; the members resolve to standing accounts', async () => {
    const res = await app.request('/scim/v2/Groups', authed({
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: 'Bulletin Authors', members: [{ value: authorId }, { value: reviewerId }] }),
    }))
    expect(res.status).toBe(201)
    const group = await res.json() as { id: string; displayName: string; members: Array<{ value: string; display: string }> }
    expect(group.displayName).toBe('Bulletin Authors')
    expect(group.members.map(m => m.value).sort()).toEqual([authorId, reviewerId].sort())
    expect(group.members[0]!.display).toBeTruthy()
  })

  it('CREATE: an UNKNOWN member refuses 400 (never a poisoned group)', async () => {
    const res = await app.request('/scim/v2/Groups', authed({
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: 'Broken', members: [{ value: 'nobody' }] }),
    }))
    expect(res.status).toBe(400)
  })

  it('LIST + FILTER: the groups list; displayName eq narrows; the bad grammar refuses', async () => {
    const listed = await app.request('/scim/v2/Groups', authed())
    const body = await listed.json() as { totalResults: number; Resources: Array<{ displayName: string }> }
    expect(body.totalResults).toBeGreaterThanOrEqual(1)
    const filtered = await app.request(`/scim/v2/Groups?filter=${encodeURIComponent('displayName eq "Bulletin Authors"')}`, authed())
    const fbody = await filtered.json() as { totalResults: number; Resources: Array<{ displayName: string }> }
    expect(fbody.totalResults).toBe(1)
    expect(fbody.Resources[0]!.displayName).toBe('Bulletin Authors')
    const bad = await app.request(`/scim/v2/Groups?filter=${encodeURIComponent('userName eq "x"')}`, authed())
    expect(bad.status).toBe(400)
  })

  it('PATCH add/remove members + replace displayName; PUT replaces wholesale; DELETE tombstones (the 404 taxonomy)', async () => {
    const created = await app.request('/scim/v2/Groups', authed({
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: 'Reviewers' }),
    }))
    const { id } = await created.json() as { id: string }

    const added = await app.request(`/scim/v2/Groups/${id}`, authed({
      method: 'PATCH', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ Operations: [{ op: 'add', path: 'members', value: [{ value: authorId }] }] }),
    }))
    expect(added.status).toBe(200)
    expect(((await added.json()) as { members: unknown[] }).members).toHaveLength(1)

    const addedAgain = await app.request(`/scim/v2/Groups/${id}`, authed({
      method: 'PATCH', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ Operations: [{ op: 'add', path: 'members', value: [{ value: authorId }, { value: reviewerId }] }] }),
    }))
    expect(((await addedAgain.json()) as { members: unknown[] }).members).toHaveLength(2) // idempotent set semantics

    const removed = await app.request(`/scim/v2/Groups/${id}`, authed({
      method: 'PATCH', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ Operations: [{ op: 'remove', path: 'members', value: [{ value: authorId }] }] }),
    }))
    expect(((await removed.json()) as { members: Array<{ value: string }> }).members.map(m => m.value)).toEqual([reviewerId])

    const renamed = await app.request(`/scim/v2/Groups/${id}`, authed({
      method: 'PATCH', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ Operations: [{ op: 'replace', path: 'displayName', value: 'Peer Reviewers' }] }),
    }))
    expect(((await renamed.json()) as { displayName: string }).displayName).toBe('Peer Reviewers')

    const replaced = await app.request(`/scim/v2/Groups/${id}`, authed({
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: 'Peer Reviewers', members: [{ value: authorId }] }),
    }))
    expect(((await replaced.json()) as { members: unknown[] }).members).toHaveLength(1)

    const gone = await app.request(`/scim/v2/Groups/${id}`, authed({ method: 'DELETE' }))
    expect(gone.status).toBe(204)
    const after = await app.request(`/scim/v2/Groups/${id}`, authed())
    expect(after.status).toBe(404)
    const listed = await app.request('/scim/v2/Groups', authed())
    expect(((await listed.json()) as { Resources: Array<{ id: string }> }).Resources.some(g => g.id === id)).toBe(false)
  })
})

describe('the surface exists only when armed', () => {
  it('UNSET = 404 everywhere under /scim (the Turnstile pattern)', async () => {
    delete process.env.SCIM_BEARER_TOKEN
    for (const path of ['/scim/v2/Users', '/scim/v2/Users/some-id']) {
      const res = await app.request(`${ISSUER}${path}`, { headers: { authorization: `Bearer ${BEARER}` } })
      expect(res.status, path).toBe(404)
    }
  })

  it('a wrong or absent bearer refuses 401 (the RFC 7644 taxonomy)', async () => {
    const noAuth = await app.request(`${ISSUER}/scim/v2/Users`)
    expect(noAuth.status).toBe(401)
    const wrong = await app.request(`${ISSUER}/scim/v2/Users`, { headers: { authorization: 'Bearer nope' } })
    expect(wrong.status).toBe(401)
    const body = await wrong.json() as { schemas: string[]; status: number }
    expect(body.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:Error')
    expect(body.status).toBe(401)
  })
})

describe('the create (POST /scim/v2/Users)', () => {
  it('provisions the invited account with the enrollment token', async () => {
    const res = await app.request(`${ISSUER}/scim/v2/Users`, authed({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'provisioned.person@example.org',
        name: { givenName: 'Provisioned', familyName: 'Person' },
        active: true,
      }),
    }))
    expect(res.status).toBe(201)
    const user = await res.json() as ScimUser
    expect(user.userName).toBe('provisioned.person@example.org')
    expect(user.active).toBe(true)
    expect(user.id).toBeTruthy()

    // The account row exists (the honest disable target).
    const account = await store.findUserByEmail('provisioned.person@example.org')
    expect(account?.id).toBe(user.id)
  })

  it('a duplicate userName refuses 409 (the RFC\'s shape)', async () => {
    const res = await app.request(`${ISSUER}/scim/v2/Users`, authed({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName: 'provisioned.person@example.org', active: true }),
    }))
    expect(res.status).toBe(409)
  })

  it('a malformed body refuses 400', async () => {
    const res = await app.request(`${ISSUER}/scim/v2/Users`, authed({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ active: true }),
    }))
    expect(res.status).toBe(400)
  })
})

describe('the reads', () => {
  it('GET /:id answers the projection; unknown = the 404 taxonomy', async () => {
    const created = await (await app.request(`${ISSUER}/scim/v2/Users`, authed({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName: 'reader@example.org', active: true }),
    }))).json() as ScimUser

    const got = await app.request(`${ISSUER}/scim/v2/Users/${created.id}`, authed())
    expect(got.status).toBe(200)
    const user = await got.json() as ScimUser
    expect(user.id).toBe(created.id)
    expect(user.name?.formatted).toBe('Reader')

    const missing = await app.request(`${ISSUER}/scim/v2/Users/ffffffff-ffff-ffff-ffff-ffffffffffff`, authed())
    expect(missing.status).toBe(404)
    const err = await missing.json() as { schemas: string[]; status: number }
    expect(err.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:Error')
  })

  it('the list paginates; filter=userName eq narrows (the supported subset)', async () => {
    const list = await app.request(`${ISSUER}/scim/v2/Users?count=2`, authed())
    expect(list.status).toBe(200)
    const body = await list.json() as { totalResults: number; startIndex: number; itemsPerPage: number; Resources: ScimUser[] }
    expect(body.totalResults).toBeGreaterThanOrEqual(2)
    expect(body.Resources.length).toBeLessThanOrEqual(2)
    expect(body.startIndex).toBe(1)

    const filtered = await app.request(
      `${ISSUER}/scim/v2/Users?filter=${encodeURIComponent('userName eq "reader@example.org"')}`,
      authed(),
    )
    const fbody = await filtered.json() as { totalResults: number; Resources: ScimUser[] }
    expect(fbody.totalResults).toBe(1)
    expect(fbody.Resources[0]!.userName).toBe('reader@example.org')
  })

  it('an unsupported filter refuses 400 with scimType invalid_filter', async () => {
    const res = await app.request(
      `${ISSUER}/scim/v2/Users?filter=${encodeURIComponent('name.givenName co "x"')}`,
      authed(),
    )
    expect(res.status).toBe(400)
    const body = await res.json() as { scimType?: string }
    expect(body.scimType).toBe('invalid_filter')
  })
})

describe('the lifecycle tail', () => {
  it('PATCH active=false disables HONESTLY (the sessions die with it)', async () => {
    const created = await (await app.request(`${ISSUER}/scim/v2/Users`, authed({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName: 'departing@example.org', active: true }),
    }))).json() as ScimUser

    // A live session for the departing account.
    const token = await store.createSession(created.id)
    expect(await store.getSessionUser(token)).not.toBeNull()

    const patched = await app.request(`${ISSUER}/scim/v2/Users/${created.id}`, authed({
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:PatchOp'],
        Operations: [{ op: 'replace', path: 'active', value: false }],
      }),
    }))
    expect(patched.status).toBe(200)
    const user = await patched.json() as ScimUser
    expect(user.active).toBe(false)

    // The honest disable: the row stays (auditable), the session is dead.
    expect(await store.getSessionUser(token)).toBeNull()
    const rows = await store.listUsers()
    expect(rows.find(r => r.id === created.id)?.active).toBe(false)
  })

  it('PATCH name renames the account (the existing rename verb, both RFC forms)', async () => {
    const created = await (await app.request(`${ISSUER}/scim/v2/Users`, authed({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName: 'renamable@example.org', active: true }),
    }))).json() as ScimUser

    // The pathful form: replace name {givenName, familyName}.
    const pathful = await app.request(`${ISSUER}/scim/v2/Users/${created.id}`, authed({
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        Operations: [{ op: 'replace', path: 'name', value: { givenName: 'Renamed', familyName: 'Person' } }],
      }),
    }))
    expect(pathful.status).toBe(200)
    expect(((await pathful.json()) as ScimUser).name?.formatted).toBe('Renamed Person')

    // The pathless form: replace value.name {formatted}.
    const pathless = await app.request(`${ISSUER}/scim/v2/Users/${created.id}`, authed({
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        Operations: [{ op: 'replace', value: { name: { formatted: 'The Flat Name' } } }],
      }),
    }))
    expect(pathless.status).toBe(200)
    expect(((await pathless.json()) as ScimUser).name?.formatted).toBe('The Flat Name')

    // The account row itself (the rename verb's truth).
    const account = await store.findUserByEmail('renamable@example.org')
    expect(account?.name).toBe('The Flat Name')
  })

  it('DELETE deactivates (never the erase)', async () => {
    const created = await (await app.request(`${ISSUER}/scim/v2/Users`, authed({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName: 'offboarded@example.org', active: true }),
    }))).json() as ScimUser

    const res = await app.request(`${ISSUER}/scim/v2/Users/${created.id}`, authed({ method: 'DELETE' }))
    expect(res.status).toBe(204)
    const rows = await store.listUsers()
    const row = rows.find(r => r.id === created.id)
    expect(row).toBeDefined()
    expect(row!.active).toBe(false)
    expect(row!.provider).not.toBe('erased')
  })
})
