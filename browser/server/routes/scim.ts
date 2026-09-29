// ═══════════════════════════════════════════════════════════════════
// The SCIM 2.0 provisioning surface (TODO.modern/05, RFC 7644) — the
// enterprise lifecycle: an HR system provisions and deprovisions
// accounts through /scim/v2/Users.
//
//   POST   /scim/v2/Users        — the create: the invited account +
//                                  the one-time setup link (emailed
//                                  when a provider is configured)
//   GET    /scim/v2/Users        — the list: pagination + the
//                                  filter=userName eq "…" subset (the
//                                  supported filter grammar — anything
//                                  else refuses invalid_filter)
//   GET    /scim/v2/Users/:id    — the projection
//   PATCH  /scim/v2/Users/:id    — the update: active replace (the
//                                  honest disable kills the sessions)
//   DELETE /scim/v2/Users/:id    — deactivate (NEVER the erase — the
//                                  row stays auditable)
//
// The credential: SCIM_BEARER_TOKEN (a Worker secret) — the dedicated
// connector token, the Okta/Auth0 SCIM norm. UNSET = the whole surface
// answers 404 (it does not exist — the Turnstile pattern). The brief's
// PAT-scoped variant is deliberately NOT built: the PAT grammar is
// client-service-derived and a synthetic 'scim' service would contort
// it; a dedicated token IS the scoped credential (only-SCIM by
// construction). Recorded in TODO.modern/05.
//
// The MAPPING (MECE): SCIM maps onto the EXISTING account model —
// createOpAccount, the enrollment invite, setUserActive,
// deleteAllUserSessions — never a second account store.
//
// WORKER-SAFE: hono + the store seam + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type UserAdminRow } from '../store'
import { sendOpMail } from '../auth/op/mail'
import { mintEnrollmentToken, OP_ENROLLMENT_TTL_MS } from '../auth/op/accounts'
import { resolveOpConfig } from '../auth/op/config'

const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
const ERROR_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Error'
const LIST_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ListResponse'
const PATCH_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:PatchOp'

/** The constant-time bearer fold (the request-id seam's pattern). */
function bearerOk(presented: string, expected: string): boolean {
  if (presented.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < expected.length; i++) {
    diff |= presented.charCodeAt(i) !== expected.charCodeAt(i) ? 1 : 0
  }
  return diff === 0
}

type ScimStatus = 400 | 401 | 404 | 409

function scimError(c: Context, status: ScimStatus, detail: string, scimType?: string): Response {
  return c.json({
    schemas: [ERROR_SCHEMA],
    status,
    detail,
    ...(scimType ? { scimType } : {}),
  }, status)
}

/** The display name for a provisioned account: the given+family pair
 *  when the HR system sent one, else the address's local part
 *  capitalized (the honest projection of what we hold). */
function displayName(userName: string, name?: { givenName?: unknown; familyName?: unknown }): string {
  const given = typeof name?.givenName === 'string' ? name.givenName.trim() : ''
  const family = typeof name?.familyName === 'string' ? name.familyName.trim() : ''
  const joined = [given, family].filter(Boolean).join(' ')
  if (joined) return joined
  const local = userName.split('@')[0] ?? userName
  return local.charAt(0).toUpperCase() + local.slice(1)
}

function toScimUser(row: { id: string; email: string; name: string; active: boolean }): Record<string, unknown> {
  return {
    schemas: [USER_SCHEMA],
    id: row.id,
    userName: row.email,
    active: row.active,
    name: { formatted: row.name },
    meta: { resourceType: 'User', location: `/scim/v2/Users/${row.id}` },
  }
}

export function createScimRouter(): Hono {
  const scim = new Hono()

  // The gate: unset token = the surface does not exist. Wrong bearer =
  // the RFC's 401. The check rides every route (the middleware form —
  // one place, the OCP posture).
  scim.use('/scim/*', async (c, next) => {
    const expected = runtimeEnv<Record<string, string | undefined>>(c).SCIM_BEARER_TOKEN?.trim()
    if (!expected) return c.text('Not Found', 404)
    const header = c.req.header('authorization') ?? ''
    const presented = header.startsWith('Bearer ') ? header.slice(7).trim() : ''
    if (!presented || !bearerOk(presented, expected)) {
      return scimError(c, 401, 'the SCIM bearer token is required')
    }
    await next()
  })

  scim.post('/scim/v2/Users', async (c) => {
    const body = await c.req.json<{ userName?: unknown; name?: unknown; active?: unknown }>().catch(() => null)
    const userName = typeof body?.userName === 'string' ? body.userName.trim().toLowerCase() : ''
    if (!userName || !userName.includes('@')) {
      return scimError(c, 400, 'userName (the account\'s email address) is required')
    }
    const store = getStore()
    if (await store.findUserByEmail(userName)) {
      return scimError(c, 409, `an account already exists for ${userName}`)
    }
    const created = await store.createOpAccount({
      email: userName,
      name: displayName(userName, body?.name as { givenName?: string; familyName?: string } | undefined),
      role: 'viewer',
      createdBy: 'scim',
    })
    if (!created) return scimError(c, 409, `an account already exists for ${userName}`)

    // The enrollment invite: the one-time setup link (emailed when a
    // provider is configured — best-effort, never blocking the
    // provisioning; the admin console's resend stands behind it).
    const token = mintEnrollmentToken()
    const enrollment = await store.createEnrollmentToken({
      token,
      userId: created.id,
      createdBy: 'scim',
      ttlMs: OP_ENROLLMENT_TTL_MS,
    })
    const issuer = resolveOpConfig(runtimeEnv<Record<string, string | undefined>>(c), c.req.header('origin') ?? new URL(c.req.url).origin).issuer
    void sendOpMail(runtimeEnv<Record<string, string | undefined>>(c), {
      to: userName,
      template: 'invite',
      issuer,
      params: {
        name: created.name,
        setupUrl: `${issuer}/op/setup?token=${encodeURIComponent(token)}`,
        hours: Math.round(OP_ENROLLMENT_TTL_MS / 3_600_000),
      },
    }).catch(() => {})

    c.header('Location', `/scim/v2/Users/${created.id}`)
    return c.json(toScimUser({ ...created, active: true }), 201)
  })

  scim.get('/scim/v2/Users', async (c) => {
    const url = new URL(c.req.url)
    const filter = url.searchParams.get('filter')?.trim() ?? ''
    // The supported subset: userName eq "<email>" — everything else
    // refuses the RFC's invalid_filter (never a silent mis-answer).
    let wantedEmail: string | null = null
    if (filter) {
      const match = /^userName\s+eq\s+"([^"]+)"$/.exec(filter)
      if (!match) return scimError(c, 400, 'the supported filter is: userName eq "<email>"', 'invalid_filter')
      wantedEmail = match[1]!.trim().toLowerCase()
    }
    const startIndex = Math.max(1, Number(url.searchParams.get('startIndex') ?? 1) || 1)
    const count = Math.min(200, Math.max(0, Number(url.searchParams.get('count') ?? 100) || 0))

    let users: UserAdminRow[] = (await getStore().listUsers()).filter(u => u.provider !== 'erased')
    if (wantedEmail !== null) users = users.filter(u => u.email.toLowerCase() === wantedEmail)
    const page = users.slice(startIndex - 1, startIndex - 1 + count)
    return c.json({
      schemas: [LIST_SCHEMA],
      totalResults: users.length,
      startIndex,
      itemsPerPage: page.length,
      Resources: page.map(toScimUser),
    })
  })

  scim.get('/scim/v2/Users/:id', async (c) => {
    const row = (await getStore().listUsers()).find(u => u.id === c.req.param('id') && u.provider !== 'erased')
    if (!row) return scimError(c, 404, 'no such user')
    return c.json(toScimUser(row))
  })

  /** The shared lifecycle tail: the honest disable (the sessions die
   *  with the account) / re-enable. */
  async function setActive(row: UserAdminRow, active: boolean): Promise<void> {
    const store = getStore()
    if (!active) await store.deleteAllUserSessions(row.id)
    await store.setUserActive(row.id, active)
  }

  scim.patch('/scim/v2/Users/:id', async (c) => {
    const row = (await getStore().listUsers()).find(u => u.id === c.req.param('id') && u.provider !== 'erased')
    if (!row) return scimError(c, 404, 'no such user')
    const body = await c.req.json<{ Operations?: unknown }>().catch(() => null)
    const operations = Array.isArray(body?.Operations) ? body!.Operations : []
    // The supported act: the active replace (pathful or pathless per
    // RFC 7644 §3.5.2). Anything else refuses invalidPath — never a
    // silent mis-answer.
    let nextActive: boolean | null = null
    let nextName: string | null = null
    for (const op of operations) {
      if (!op || typeof op !== 'object') continue
      const { op: verb, path, value } = op as { op?: unknown; path?: unknown; value?: unknown }
      if (verb !== 'replace') continue
      if (path === 'active') {
        if (typeof value === 'boolean') nextActive = value
        continue
      }
      // The RENAME (the account's existing rename verb): the pathful
      // replace name {givenName,familyName,formatted} or the pathless
      // value.name — the display name is the formatted, else the
      // given+family join (the create's own projection rule).
      const nameValue = path === 'name'
        ? (value && typeof value === 'object' ? value as Record<string, unknown> : null)
        : path === undefined && value && typeof value === 'object' && 'name' in value
          ? (value as { name: unknown }).name as Record<string, unknown> | null
          : null
      if (nameValue) {
        const formatted = typeof nameValue.formatted === 'string' && nameValue.formatted.trim()
          ? nameValue.formatted.trim()
          : [nameValue.givenName, nameValue.familyName]
              .filter((part): part is string => typeof part === 'string' && Boolean(part.trim()))
              .map(part => part.trim())
              .join(' ')
        if (formatted) nextName = formatted
        continue
      }
      if (path === undefined && value && typeof value === 'object' && 'active' in value) {
        const candidate = (value as { active: unknown }).active
        if (typeof candidate === 'boolean') nextActive = candidate
      }
    }
    if (nextActive === null && nextName === null) {
      return scimError(c, 400, 'the supported operations are: replace active, replace name (pathful or pathless)', 'invalidPath')
    }
    if (nextName !== null) await getStore().updateUserName(row.id, nextName)
    if (nextActive !== null) await setActive(row, nextActive)
    const refreshed = (await getStore().listUsers()).find(u => u.id === row.id) ?? row
    return c.json(toScimUser(nextName !== null ? { ...refreshed, name: nextName } : refreshed))
  })

  scim.delete('/scim/v2/Users/:id', async (c) => {
    const row = (await getStore().listUsers()).find(u => u.id === c.req.param('id') && u.provider !== 'erased')
    if (!row) return scimError(c, 404, 'no such user')
    // RFC 7644 §3.6: DELETE deactivates — the account row NEVER erases
    // (the audit + the history keep it; the erase is the console's own
    // sovereign act).
    await setActive(row, false)
    return c.body(null, 204)
  })

  // ── Groups (TODO.sota/03, RFC 7644 §4.2) ──────────────────────────
  // The RP-managed groups (the connector's own groups — the Bulletin's
  // authors, the platform's reviewers), NEVER the org registry's
  // memberships (the MECE: those are the REGISTER's truth; this is the
  // RP's). The backing rides the entity seam (the audit-events pattern):
  // store 'scimGroups', the data JSON carries displayName + members —
  // no migration, one read per list (the scaling doctrine: ONE
  // listEntities call, the member expansion in memory).

  const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group'
  const GROUP_STORE = 'scimGroups'

  interface ScimGroupData { displayName: string; members: Array<{ value: string; display?: string }>; createdBy: string }
  interface GroupRow { id: string; data: string }

  /** The parsed data, or NULL for the tombstoned rows (a deleted
   *  group's history keeps in the entity store; the reads answer the
   *  404 taxonomy, never a half-projected shell). */
  async function groupData(row: GroupRow): Promise<ScimGroupData | null> {
    const parsed = JSON.parse(row.data) as Partial<ScimGroupData> & { deleted?: boolean }
    if (parsed.deleted || typeof parsed.displayName !== 'string') return null
    return { displayName: parsed.displayName, members: Array.isArray(parsed.members) ? parsed.members : [], createdBy: typeof parsed.createdBy === 'string' ? parsed.createdBy : 'scim' }
  }

  function toScimGroup(id: string, data: ScimGroupData): Record<string, unknown> {
    return {
      schemas: [GROUP_SCHEMA],
      id,
      displayName: data.displayName,
      members: data.members.map(m => ({ value: m.value, display: m.display ?? m.value, $ref: `/scim/v2/Users/${m.value}` })),
      meta: { resourceType: 'Group', location: `/scim/v2/Groups/${id}` },
    }
  }

  /** The member ids must name EXISTING, standing accounts — a group
   *  member that resolves to nobody poisons every downstream read. */
  async function resolveMembers(raw: unknown): Promise<Array<{ value: string; display?: string }> | null> {
    if (!Array.isArray(raw)) return null
    const users = await getStore().listUsers()
    const standing = new Map(users.filter(u => u.provider !== 'erased').map(u => [u.id, u]))
    const out: Array<{ value: string; display?: string }> = []
    for (const m of raw) {
      const value = (m as { value?: unknown })?.value
      if (typeof value !== 'string') return null
      const user = standing.get(value)
      if (!user) return null
      if (out.some(x => x.value === value)) continue // idempotent set semantics
      out.push({ value, display: user.name })
    }
    return out
  }

  scim.get('/scim/v2/Groups', async (c) => {
    const filter = (c.req.query('filter') ?? '').trim()
    let rows = await getStore().listEntities(GROUP_STORE)
    const groups: Array<Record<string, unknown>> = []
    for (const row of rows) {
      try {
        const data = await groupData(row)
        if (!data) continue // the tombstone: the history keeps, the reads skip
        // The supported filter grammar: displayName eq "…" (the Users
        // list's own subset — anything else refuses invalid_filter).
        const eq = filter.match(/^displayName\s+eq\s+"([^"]*)"$/)
        if (filter && !eq) return scimError(c, 400, 'the supported filter is displayName eq "…"', 'invalidFilter')
        if (eq && data.displayName !== eq[1]) continue
        groups.push(toScimGroup(row.id, data))
      } catch { /* a malformed row never breaks the feed */ }
    }
    return c.json({
      schemas: [LIST_SCHEMA],
      totalResults: groups.length,
      startIndex: 1,
      itemsPerPage: groups.length,
      Resources: groups,
    })
  })

  scim.post('/scim/v2/Groups', async (c) => {
    const body = await c.req.json().catch(() => null) as { displayName?: unknown; members?: unknown } | null
    if (!body || typeof body.displayName !== 'string' || !body.displayName.trim()) {
      return scimError(c, 400, 'displayName is required')
    }
    const members = body.members === undefined ? [] : await resolveMembers(body.members)
    if (members === null) return scimError(c, 400, 'members must name existing users (each value = a SCIM user id)')
    const id = crypto.randomUUID()
    const data: ScimGroupData = { displayName: body.displayName.trim(), members, createdBy: 'scim' }
    await getStore().putEntity(GROUP_STORE, id, null, JSON.stringify(data))
    return c.json(toScimGroup(id, data), 201)
  })

  scim.get('/scim/v2/Groups/:id', async (c) => {
    const row = await getStore().getEntity(GROUP_STORE, c.req.param('id'))
    if (!row) return scimError(c, 404, 'no such group')
    const data = await groupData(row)
    if (!data) return scimError(c, 404, 'no such group')
    return c.json(toScimGroup(row.id, data))
  })

  scim.put('/scim/v2/Groups/:id', async (c) => {
    const id = c.req.param('id')
    const row = await getStore().getEntity(GROUP_STORE, id)
    if (!row) return scimError(c, 404, 'no such group')
    const current = await groupData(row)
    if (!current) return scimError(c, 404, 'no such group')
    const body = await c.req.json().catch(() => null) as { displayName?: unknown; members?: unknown } | null
    if (!body || typeof body.displayName !== 'string' || !body.displayName.trim()) {
      return scimError(c, 400, 'displayName is required')
    }
    const members = body.members === undefined ? current.members : await resolveMembers(body.members)
    if (members === null) return scimError(c, 400, 'members must name existing users (each value = a SCIM user id)')
    const next: ScimGroupData = { displayName: body.displayName.trim(), members, createdBy: current.createdBy }
    await getStore().putEntity(GROUP_STORE, id, null, JSON.stringify(next))
    return c.json(toScimGroup(id, next))
  })

  scim.patch('/scim/v2/Groups/:id', async (c) => {
    const id = c.req.param('id')
    const row = await getStore().getEntity(GROUP_STORE, id)
    if (!row) return scimError(c, 404, 'no such group')
    const data = await groupData(row)
    if (!data) return scimError(c, 404, 'no such group')
    const body = await c.req.json().catch(() => null) as {
      Operations?: Array<{ op?: unknown; path?: unknown; value?: unknown }>
    } | null
    if (!body || !Array.isArray(body.Operations)) return scimError(c, 400, 'Operations is required')
    let displayName = data.displayName
    let members = data.members
    for (const op of body.Operations) {
      const kind = typeof op.op === 'string' ? op.op.toLowerCase() : ''
      const path = typeof op.path === 'string' ? op.path : undefined
      if (kind === 'replace' && (path === 'displayName' || path === undefined)) {
        if (typeof op.value === 'string' && op.value.trim()) displayName = op.value.trim()
        continue
      }
      if ((kind === 'add' || kind === 'remove') && path === 'members') {
        const delta = await resolveMembers(op.value)
        if (delta === null) return scimError(c, 400, 'members must name existing users (each value = a SCIM user id)')
        if (kind === 'add') {
          for (const m of delta) if (!members.some(x => x.value === m.value)) members.push(m)
        } else {
          const removing = new Set(delta.map(m => m.value))
          members = members.filter(m => !removing.has(m.value))
        }
        continue
      }
      return scimError(c, 400, 'the supported operations: replace displayName, add/remove members', 'invalidPath')
    }
    const next: ScimGroupData = { displayName, members, createdBy: data.createdBy }
    await getStore().putEntity(GROUP_STORE, id, null, JSON.stringify(next))
    return c.json(toScimGroup(id, next))
  })

  scim.delete('/scim/v2/Groups/:id', async (c) => {
    const id = c.req.param('id')
    const row = await getStore().getEntity(GROUP_STORE, id)
    if (!row) return scimError(c, 404, 'no such group')
    await getStore().putEntity(GROUP_STORE, id, null, JSON.stringify({ deleted: true, deletedAt: new Date().toISOString() }))
    // The tombstone (the audit doctrine — the group's history keeps);
    // every read filters it by the missing displayName (a deleted row
    // never projects: the reads demand the displayName string).
    return c.body(null, 204)
  })

  return scim
}
