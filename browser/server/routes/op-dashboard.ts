// ═══════════════════════════════════════════════════════════════════
// The administrator's dashboard API (TODO.identity-sso/01) — the read
// surface behind the OP's admin console (/op/admin): the overview's
// metrics, the aggregate live-session view with its force-revoke acts,
// the security signals, the queryable + exportable audit log, the live
// access review, and the per-client activity. Every answer derives from
// the SAME three sources the rest of the service already keeps — the
// auditEvents journal, the store seam, and the heartbeat workflow's own
// history on GitHub. There is no separate monitoring pipeline.
//
// The surface (profile-gated like every OP route — a non-identity
// deployment answers 404; admin-gated like routes/op-registry.ts — the
// platform admin and the scheme operator):
//
//   GET  /api/op/dashboard/overview     — the tiles: accounts by
//                                         lifecycle state (invited /
//                                         active / deactivated), sign-ins
//                                         succeeded/failed per UTC day
//                                         (14 days), today's anomaly
//                                         counts, the live-session count,
//                                         the retention statement
//   GET  /api/op/dashboard/heartbeat    — the SLO panel's data: the
//                                         identity-heartbeat workflow's
//                                         run history, read from the
//                                         GitHub Actions API at its
//                                         source (the probe's results
//                                         live THERE, never in the OP);
//                                         degrades honestly to a link
//   GET  /api/op/dashboard/sessions     — the aggregate "who is signed
//                                         in NOW": every live OP session
//                                         with its account, the user
//                                         agent + IP, issued/last-seen/
//                                         expiry. NEVER a token value
//   POST /api/op/dashboard/accounts/:id/sessions/revoke-all
//                                       — the light act: end EVERY
//                                         session of the account (the
//                                         per-account single revoke is
//                                         routes/op-registry.ts's; the
//                                         heavy act — deactivation — is
//                                         routes/users.ts's). Audited.
//   GET  /api/op/dashboard/security     — the security signals: failed-
//                                         login bursts (the threshold is
//                                         stated), token-endpoint
//                                         refusals, rate-limit trips,
//                                         new upstream links, new client
//                                         registrations
//   GET  /api/op/dashboard/audit        — the queryable audit log:
//                                         q/action/entity_type/from/to/
//                                         limit filters; format=csv is
//                                         the export (an attachment)
//   GET  /api/op/dashboard/access-review— the quarterly access review's
//                                         LIVE version (scripts/
//                                         op-access-review.ts's rule set
//                                         over the store seam): the
//                                         privileged holders, the
//                                         per-client privileged grants,
//                                         the findings, the posture
//   GET  /api/op/dashboard/clients      — the per-client activity:
//                                         tokens issued per UTC day (14
//                                         days), the refusal counts, the
//                                         registry's own events
//
// The rules the spec pins, kept here: every admin act writes an audit
// event (the revoke-all below does; the neighboring routers carry the
// rest); no session read ever exposes a token value; every route is
// admin/cs_admin gated; the monitoring answers carry their retention
// statement; this router never writes except through the store's own
// revocation halves (never a bypass of the API's gates).
//
// WORKER-SAFE: the store seam + fetch only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { getCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type AuthUserPayload } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { SESSION_COOKIE, sessionUser } from '@oimlsmart/platform-server/session'
import { APP_ROLES } from '@oimlsmart/platform-server/vocab'

/** The audit journal's parsed row (the shape every writer serializes). */
interface AuditEvent {
  id: string
  timestamp: string
  entity_type: string
  entity_id: string
  action: string
  user_id?: string
  user_name?: string
  metadata?: Record<string, unknown>
}

function parseAuditEvent(data: string): AuditEvent | null {
  try {
    const parsed = JSON.parse(data) as AuditEvent
    if (typeof parsed?.id !== 'string' || typeof parsed?.action !== 'string' || typeof parsed?.timestamp !== 'string') return null
    return parsed
  } catch {
    return null
  }
}

/** The sign-in outcome families the overview + security surfaces count. */
const SIGN_IN_OK = new Set(['account.sign_in', 'upstream_sign_in'])
const SIGN_IN_FAIL = new Set(['account.sign_in_failed', 'upstream_refused'])
/** The failed-login burst rule (stated in the answer, never hidden):
 *  one account or address with this many failed sign-ins inside 24 hours
 *  is a burst. */
const FAILED_LOGIN_BURST_THRESHOLD = 5
/** The overview + client activity series depth (UTC day buckets). */
const SERIES_DAYS = 14

/** The monitoring answers' retention statement (the spec's rule: the
 *  monitoring data carries it). The audit journal is D1-resident with
 *  no automated purge; the heartbeat's history is GitHub Actions' own
 *  (its retention is GitHub's); the derived counters are computed at
 *  request time and keep nothing. */
const RETENTION_STATEMENT =
  'The audit journal is retained for the life of the registry (no automated purge). '
  + 'The heartbeat history is retained by GitHub Actions under its own policy. '
  + 'The dashboard computes its counters at request time and stores nothing.'

const dayKey = (iso: string): string => iso.slice(0, 10)

/** The 14-UTC-day bucket skeleton ending today (zero-filled). */
function dayBuckets(): Map<string, { succeeded: number; failed: number }> {
  const buckets = new Map<string, { succeeded: number; failed: number }>()
  for (let i = SERIES_DAYS - 1; i >= 0; i--) {
    buckets.set(new Date(Date.now() - i * 86_400_000).toISOString().slice(0, 10), { succeeded: 0, failed: 0 })
  }
  return buckets
}

async function readJournal(): Promise<AuditEvent[]> {
  return (await getStore().listEntities('auditEvents'))
    .map(row => parseAuditEvent(row.data))
    .filter((e): e is AuditEvent => !!e)
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
}

// ── the heartbeat's history (the SLO panel) ──────────────────────────
// The probe (browser/scripts/op-heartbeat.ts) runs as the
// identity-heartbeat GitHub Actions workflow; its results live in the
// workflow's run history and NOWHERE else — so the panel reads the
// GitHub Actions API at the source. The repository is public, so the
// unauthenticated read suffices; the per-isolate cache (five minutes)
// keeps the courtesy rate limit distant, and any failure degrades the
// panel to the honest link, never to a fabricated number.

interface HeartbeatAnswer {
  available: boolean
  reason?: string
  source: { repo: string; workflow: string; runsUrl: string }
  window?: { runs: number; since: string | null; note: string }
  totals?: { completed: number; succeeded: number; failed: number; successRate: number | null }
  lastRun?: { at: string; conclusion: string | null; url: string } | null
  failures?: Array<{ at: string; url: string }>
  fetchedAt: string
}

interface WorkflowRun {
  id: number
  status: string | null
  conclusion: string | null
  created_at: string
  html_url: string
}

const heartbeatCache = new Map<string, { at: number; answer: HeartbeatAnswer }>()
const HEARTBEAT_CACHE_TTL_MS = 5 * 60 * 1000

async function readHeartbeat(env: Record<string, string | undefined>): Promise<HeartbeatAnswer> {
  const apiBase = (env.OP_HEARTBEAT_API_BASE ?? 'https://api.github.com').replace(/\/+$/, '')
  const repo = env.OP_HEARTBEAT_REPO ?? 'oimlsmart/identity'
  const workflow = env.OP_HEARTBEAT_WORKFLOW ?? 'identity-heartbeat.yml'
  const source = { repo, workflow, runsUrl: `https://github.com/${repo}/actions/workflows/${workflow}` }

  const cacheKey = `${apiBase}|${repo}|${workflow}`
  const cached = heartbeatCache.get(cacheKey)
  if (cached && Date.now() - cached.at < HEARTBEAT_CACHE_TTL_MS) return cached.answer

  let answer: HeartbeatAnswer
  try {
    const res = await fetch(`${apiBase}/repos/${repo}/actions/workflows/${workflow}/runs?per_page=100`, {
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'oimlsmart-identity-op' },
    })
    if (!res.ok) {
      answer = {
        available: false,
        reason: `the workflow history read answered HTTP ${res.status} — the run history itself lives at the link`,
        source,
        fetchedAt: new Date().toISOString(),
      }
    } else {
      const body = await res.json() as { workflow_runs?: WorkflowRun[] }
      const runs = (body.workflow_runs ?? []).map(r => ({
        id: r.id,
        status: r.status,
        conclusion: r.conclusion,
        created_at: r.created_at,
        html_url: r.html_url,
      }))
      const completed = runs.filter(r => r.status === 'completed')
      const succeeded = completed.filter(r => r.conclusion === 'success')
      const failed = completed.filter(r => r.conclusion === 'failure')
      answer = {
        available: true,
        source,
        window: {
          runs: runs.length,
          since: runs.at(-1)?.created_at ?? null,
          note: `the ${runs.length} most recent runs the API answers (the 15-minute cadence; the full history lives at the link)`,
        },
        totals: {
          completed: completed.length,
          succeeded: succeeded.length,
          failed: failed.length,
          successRate: completed.length ? succeeded.length / completed.length : null,
        },
        lastRun: runs[0]
          ? { at: runs[0].created_at, conclusion: runs[0].conclusion, url: runs[0].html_url }
          : null,
        failures: failed.slice(0, 10).map(r => ({ at: r.created_at, url: r.html_url })),
        fetchedAt: new Date().toISOString(),
      }
    }
  } catch (err) {
    answer = {
      available: false,
      reason: `the workflow history read failed (${(err as Error).message}) — the run history itself lives at the link`,
      source,
      fetchedAt: new Date().toISOString(),
    }
  }
  heartbeatCache.set(cacheKey, { at: Date.now(), answer })
  return answer
}

export function createOpDashboardRouter(): Hono {
  const dashboard = new Hono()

  // ── the profile gate (the same posture as routes/op-registry.ts) ────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  dashboard.use('/api/op/dashboard/*', profileGate)

  /** The admin gate (the same rule as the registry surface: the platform
   *  admin and the scheme operator). */
  async function requireAdmin(c: Context): Promise<{ user: AuthUserPayload | null; error: Response | null }> {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    if (user.role !== 'admin' && user.role !== 'cs_admin') {
      return { user: null, error: c.json({ error: 'administrator role required' }, 403) }
    }
    return { user, error: null }
  }

  /** The revoke-all act's audit row (entity_type 'account', the same
   *  journal family as the neighboring registry acts; never blocks). */
  async function audit(
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
  ): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: 'account',
        entity_id: entityId,
        action,
        user_id: actor.userId,
        user_name: actor.userName,
        metadata,
      }))
    } catch (err) {
      console.error(`[op] dashboard audit event ${action} failed to persist:`, (err as Error).message)
    }
  }

  // GET /api/op/dashboard/overview — the tiles' data.
  dashboard.get('/api/op/dashboard/overview', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const [users, journal, live] = await Promise.all([
      store.listUsers(),
      readJournal(),
      store.listOpLiveSessions(),
    ])

    // The lifecycle split. "invited" is honest: an active password
    // account whose credential was never set (the enrollment is
    // outstanding); it cannot sign in until the setup link completes.
    let invited = 0
    await Promise.all(users.map(async u => {
      if (!u.active || u.provider !== 'password') return
      const methods = await store.countSignInMethods(u.id)
      if (!methods.password) invited += 1
    }))

    const days = dayBuckets()
    const today = dayKey(new Date().toISOString())
    const anomalies = { failedSignIns: 0, rateLimited: 0, tokenRefusals: 0, newLinks: 0, newClients: 0 }
    for (const e of journal) {
      const bucket = days.get(dayKey(e.timestamp))
      if (bucket) {
        if (SIGN_IN_OK.has(e.action)) bucket.succeeded += 1
        else if (SIGN_IN_FAIL.has(e.action)) bucket.failed += 1
      }
      if (dayKey(e.timestamp) !== today) continue
      if (SIGN_IN_FAIL.has(e.action)) anomalies.failedSignIns += 1
      else if (e.action === 'rate_limited') anomalies.rateLimited += 1
      else if (e.action === 'client.token_refused') anomalies.tokenRefusals += 1
      else if (e.action === 'upstream_link' || e.action === 'account.link_on_behalf') anomalies.newLinks += 1
      else if (e.action === 'client.registered') anomalies.newClients += 1
    }
    const series = [...days.entries()].map(([date, counts]) => ({ date, ...counts }))

    return c.json({
      generatedAt: new Date().toISOString(),
      retention: RETENTION_STATEMENT,
      accounts: {
        total: users.length,
        active: users.filter(u => u.active).length,
        deactivated: users.filter(u => !u.active).length,
        invited,
      },
      signIns: {
        days: series,
        totals: {
          succeeded: series.reduce((n, d) => n + d.succeeded, 0),
          failed: series.reduce((n, d) => n + d.failed, 0),
        },
        note: 'UTC day buckets from the audit journal (account.sign_in + upstream_sign_in against account.sign_in_failed + upstream_refused)',
      },
      anomaliesToday: anomalies,
      liveSessions: live.length,
    })
  })

  // GET /api/op/dashboard/heartbeat — the SLO panel's data (the workflow
  // history read at its source; the honest degradation is a 200 with
  // available:false + the link, so the panel never fabricates).
  dashboard.get('/api/op/dashboard/heartbeat', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const answer = await readHeartbeat(runtimeEnv<Record<string, string | undefined>>(c))
    return c.json(answer)
  })

  // GET /api/op/dashboard/sessions — the aggregate "who is signed in
  // NOW". The account join rides listUsers; the presenting
  // administrator's own row is marked current (computed in SQL — no
  // token value ever leaves the store or enters this answer).
  dashboard.get('/api/op/dashboard/sessions', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const [sessions, users] = await Promise.all([
      store.listOpLiveSessions(getCookie(c, SESSION_COOKIE) ?? undefined),
      store.listUsers(),
    ])
    const byId = new Map(users.map(u => [u.id, u]))
    return c.json({
      generatedAt: new Date().toISOString(),
      retention: RETENTION_STATEMENT,
      sessions: sessions.map(s => {
        const account = byId.get(s.userId)
        return {
          id: s.id,
          account: account
            ? { id: account.id, name: account.name, email: account.email, active: account.active }
            : { id: s.userId, name: null, email: null, active: null },
          createdAt: s.createdAt,
          expiresAt: s.expiresAt,
          lastSeenAt: s.lastSeenAt,
          userAgent: s.userAgent,
          ip: s.ip,
          current: s.current,
        }
      }),
    })
  })

  // POST /api/op/dashboard/accounts/:id/sessions/revoke-all — the light
  // act on the live-sessions ladder: end EVERY session of the account
  // (the single-session revoke is routes/op-registry.ts's; the heavy
  // act — deactivation, which also revokes the issued OIDC tokens and
  // blocks issuance — is routes/users.ts's). Relying-party access tokens
  // already issued keep their own short lifetimes; the console says so.
  dashboard.post('/api/op/dashboard/accounts/:id/sessions/revoke-all', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const user = await store.getUserById(c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const revoked = await store.deleteAllUserSessions(user.id)
    await audit('account.sessions_revoked', user.id, { userId: gate.user.id, userName: gate.user.name }, {
      email: user.email,
      count: revoked,
      by: 'administrator',
    })
    return c.json({ ok: true, revoked })
  })

  // GET /api/op/dashboard/security — the security signals over the
  // journal, windows stated.
  dashboard.get('/api/op/dashboard/security', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const [journal, users] = await Promise.all([readJournal(), store.listUsers()])
    const emailById = new Map(users.map(u => [u.id, u.email]))
    const now = Date.now()
    const dayAgo = new Date(now - 86_400_000).toISOString()
    const weekAgo = new Date(now - 7 * 86_400_000).toISOString()

    const failedDay = journal.filter(e => SIGN_IN_FAIL.has(e.action) && e.timestamp >= dayAgo)
    const failedWeek = journal.filter(e => SIGN_IN_FAIL.has(e.action) && e.timestamp >= weekAgo)
    const perKey = new Map<string, number>()
    for (const e of failedDay) perKey.set(e.entity_id, (perKey.get(e.entity_id) ?? 0) + 1)
    const bursts = [...perKey.entries()]
      .filter(([, n]) => n >= FAILED_LOGIN_BURST_THRESHOLD)
      .map(([key, n]) => ({
        key,
        // The burst key is the account id when the address named an
        // account (the journal's entity discipline); the console reads
        // the resolved email, never the bare uuid.
        account: emailById.get(key) ?? null,
        count24h: n,
      }))
      .sort((a, b) => b.count24h - a.count24h)

    const refusals = journal.filter(e => e.action === 'client.token_refused')
    const refusalsDay = refusals.filter(e => e.timestamp >= dayAgo)
    const refusalsWeek = refusals.filter(e => e.timestamp >= weekAgo)
    const byError: Record<string, number> = {}
    const byClient: Record<string, number> = {}
    for (const e of refusalsWeek) {
      const code = String(e.metadata?.error ?? 'unknown')
      byError[code] = (byError[code] ?? 0) + 1
      byClient[e.entity_id] = (byClient[e.entity_id] ?? 0) + 1
    }

    const trips = journal.filter(e => e.action === 'rate_limited')
    const tripsDay = trips.filter(e => e.timestamp >= dayAgo)
    const tripsWeek = trips.filter(e => e.timestamp >= weekAgo)
    const byCaller: Record<string, number> = {}
    const byPath: Record<string, number> = {}
    for (const e of tripsWeek) {
      byCaller[e.entity_id] = (byCaller[e.entity_id] ?? 0) + 1
      const path = String(e.metadata?.path ?? 'unknown')
      byPath[path] = (byPath[path] ?? 0) + 1
    }

    const newLinks = journal
      .filter(e => (e.action === 'upstream_link' || e.action === 'account.link_on_behalf') && e.timestamp >= weekAgo)
      .map(e => ({
        at: e.timestamp,
        action: e.action,
        account: String(e.metadata?.email ?? e.entity_id),
        provider: String(e.metadata?.provider ?? ''),
        by: e.user_name ?? 'the account holder',
      }))
    const newClients = journal
      .filter(e => e.action === 'client.registered' && e.timestamp >= weekAgo)
      .map(e => ({ at: e.timestamp, clientId: e.entity_id, by: e.user_name ?? 'unknown' }))

    return c.json({
      generatedAt: new Date().toISOString(),
      retention: RETENTION_STATEMENT,
      windows: { day: 'the last 24 hours', week: 'the last 7 days' },
      signals: {
        failedSignIns: {
          day: failedDay.length,
          week: failedWeek.length,
          threshold: FAILED_LOGIN_BURST_THRESHOLD,
          rule: `an account or address with ${FAILED_LOGIN_BURST_THRESHOLD}+ failed sign-ins inside 24 hours is a burst`,
          bursts,
        },
        tokenRefusals: { day: refusalsDay.length, week: refusalsWeek.length, byError, byClient },
        rateLimited: { day: tripsDay.length, week: tripsWeek.length, byCaller, byPath },
        newLinks: { week: newLinks.length, events: newLinks },
        newClients: { week: newClients.length, events: newClients },
      },
    })
  })

  // GET /api/op/dashboard/audit — the queryable, exportable audit log.
  // format=json (default) answers the parsed events; format=csv answers
  // the attachment (the same filters apply; caps stated).
  dashboard.get('/api/op/dashboard/audit', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const format = c.req.query('format') ?? 'json'
    if (format !== 'json' && format !== 'csv') {
      return c.json({ error: "format is 'json' or 'csv'" }, 400)
    }
    const q = (c.req.query('q') ?? '').trim().toLowerCase()
    const actionPrefix = (c.req.query('action') ?? '').trim()
    const entityType = (c.req.query('entity_type') ?? '').trim()
    const from = (c.req.query('from') ?? '').trim()
    const to = (c.req.query('to') ?? '').trim()
    const limitCap = format === 'csv' ? 5000 : 1000
    const limitRaw = Number(c.req.query('limit') ?? String(format === 'csv' ? 5000 : 200))
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(Math.trunc(limitRaw), 1), limitCap) : (format === 'csv' ? 5000 : 200)

    let events = await readJournal()
    if (entityType) events = events.filter(e => e.entity_type === entityType)
    if (actionPrefix) events = events.filter(e => e.action.startsWith(actionPrefix))
    if (from) events = events.filter(e => e.timestamp >= from)
    if (to) events = events.filter(e => e.timestamp <= to)
    if (q) {
      events = events.filter(e => [e.action, e.user_name ?? '', e.entity_id, String(e.metadata?.email ?? '')]
        .some(s => s.toLowerCase().includes(q)))
    }
    const page = events.slice(0, limit)

    if (format === 'json') {
      return c.json({
        generatedAt: new Date().toISOString(),
        retention: RETENTION_STATEMENT,
        total: events.length,
        returned: page.length,
        events: page,
      })
    }

    const escapeCsv = (value: string): string => `"${value.replaceAll('"', '""')}"`
    const lines = [
      'timestamp,action,entity_type,entity_id,user_name,user_id,metadata',
      ...page.map(e => [
        e.timestamp,
        e.action,
        e.entity_type,
        e.entity_id,
        e.user_name ?? '',
        e.user_id ?? '',
        JSON.stringify(e.metadata ?? {}),
      ].map(escapeCsv).join(',')),
    ]
    return new Response(`${lines.join('\n')}\n`, {
      headers: {
        'content-type': 'text/csv; charset=utf-8',
        'content-disposition': `attachment; filename="op-audit-${new Date().toISOString().slice(0, 10)}.csv"`,
      },
    })
  })

  // GET /api/op/dashboard/access-review — the quarterly review's live
  // version: the same rule set as scripts/op-access-review.ts, answered
  // from the store seam at request time.
  dashboard.get('/api/op/dashboard/access-review', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const [users, clientRoles, clients, providers, keys, signIns] = await Promise.all([
      store.listUsers(),
      store.listAllOpClientRoles(),
      store.listOidcClients(),
      store.listIdentityProviders(),
      store.listOidcKeys(),
      store.lastAccountSignIns(),
    ])
    const PRIVILEGED = ['admin', 'cs_admin', 'org_admin']
    const effectiveRoles = (u: { role: string; roles?: string[] }): string[] =>
      u.roles?.length ? u.roles : [u.role]
    const privileged = users.filter(u => effectiveRoles(u).some(r => PRIVILEGED.includes(r)))
    const lastSignIn = (id: string, fallback: string | null): string | null => signIns[id] ?? fallback

    const byId = new Map(users.map(u => [u.id, u]))
    const perClientPrivileged = clientRoles
      .filter(a => a.roles.some(r => PRIVILEGED.includes(r)))
      .map(a => ({
        account: byId.get(a.userId)?.email ?? a.userId,
        clientId: a.clientId,
        roles: a.roles.filter(r => PRIVILEGED.includes(r)),
        assignedBy: a.assignedBy,
        updatedAt: a.updatedAt,
      }))

    const findings: string[] = []
    const knownRoles = new Set<string>(APP_ROLES)
    for (const u of users) {
      const unknown = effectiveRoles(u).filter(r => !knownRoles.has(r))
      if (unknown.length) findings.push(`${u.email} carries role(s) outside the platform vocabulary: ${unknown.join(', ')}`)
    }
    for (const u of privileged) {
      if (!u.active) findings.push(`${u.email} holds a privileged role while the account is DISABLED (the row stays for the audit trail; confirm the disable is intended)`)
      if (!lastSignIn(u.id, u.lastLogin)) findings.push(`${u.email} (privileged) has never signed in`)
    }
    for (const client of clients.filter(client => client.status !== 'active')) {
      findings.push(`RP client ${client.clientId} is ${client.status} (kept for the audit trail; confirm it stays disabled)`)
    }
    for (const provider of providers.filter(p => !p.enabled)) {
      findings.push(`upstream provider ${provider.id} is disabled (its links stay; confirm it should)`)
    }
    const retiredKeys = keys.filter(k => k.status === 'retired')
    if (retiredKeys.length) findings.push(`${retiredKeys.length} retired signing key row(s) remain in the history (expected: the rotation ceremony's trail)`)

    return c.json({
      generatedAt: new Date().toISOString(),
      source: 'computed live from the registry through the store seam; the quarterly review artifact is scripts/op-access-review.ts (the same rule set)',
      privilegedRoles: PRIVILEGED,
      privilegedHolders: privileged.map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        roles: effectiveRoles(u).filter(r => PRIVILEGED.includes(r)),
        active: u.active,
        lastLogin: lastSignIn(u.id, u.lastLogin),
        emailVerifiedAt: u.emailVerifiedAt ?? null,
      })),
      perClientPrivileged,
      findings,
      posture: {
        accounts: { total: users.length, active: users.filter(u => u.active).length },
        clients: { total: clients.length, active: clients.filter(client => client.status === 'active').length },
        providers: { total: providers.length, enabled: providers.filter(p => p.enabled).length },
        signingKeys: { history: keys.length, active: keys.filter(k => k.status === 'active').length },
      },
    })
  })

  // GET /api/op/dashboard/clients — the per-client activity: issuance
  // per UTC day (14 days) + refusals + the registry's own events, per
  // registered client. The registry rows themselves stay GET
  // /api/op/clients (routes/op.ts); the console page merges by clientId.
  dashboard.get('/api/op/dashboard/clients', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const [clients, journal] = await Promise.all([store.listOidcClients(), readJournal()])

    const days = [...dayBuckets().keys()]
    const rows = clients.map(client => {
      const issuedByDay = new Map(days.map(d => [d, 0]))
      let lastIssuedAt: string | null = null
      let refusals14d = 0
      const events: Array<{ at: string; action: string; by: string }> = []
      for (const e of journal) {
        if (e.entity_id !== client.clientId) continue
        if (e.action === 'client.token_issued') {
          const day = dayKey(e.timestamp)
          if (issuedByDay.has(day)) issuedByDay.set(day, issuedByDay.get(day)! + 1)
          if (!lastIssuedAt || e.timestamp > lastIssuedAt) lastIssuedAt = e.timestamp
        } else if (e.action === 'client.token_refused') {
          if (issuedByDay.has(dayKey(e.timestamp))) refusals14d += 1
        } else if (e.action === 'client.registered' || e.action === 'client.updated' || e.action === 'client.status') {
          events.push({ at: e.timestamp, action: e.action, by: e.user_name ?? 'unknown' })
        }
      }
      const series = days.map(date => ({ date, issued: issuedByDay.get(date) ?? 0 }))
      return {
        clientId: client.clientId,
        activity: {
          days: series,
          totalIssued14d: series.reduce((n, d) => n + d.issued, 0),
          lastIssuedAt,
          refusals14d,
        },
        registryEvents: events.slice(0, 10),
      }
    })
    return c.json({
      generatedAt: new Date().toISOString(),
      retention: RETENTION_STATEMENT,
      clients: rows,
    })
  })

  return dashboard
}
