// ═══════════════════════════════════════════════════════════════════
// The session + demo sign-in seam (the extraction map, smart's
// PROGRESS/41 §3): the identity repo does NOT carry the platform's
// routes/auth.ts (the RP half — SSO/GitHub sign-in, the approval queue,
// claim mapping). What the OP's own pages and tests need from it is
// exactly four endpoints, re-implemented here on the kernel's session
// seam (the cookie name and the sessions-table semantics are the
// contract — live sessions survive the extraction):
//
//   GET  /api/auth/session          the session's user payload, 401 null
//   POST /api/auth/demo             the demo-cast sign-in (the
//                                   development/e2e/preview posture;
//                                   gated by demoAccountsEnabled)
//   GET  /api/auth/demo-accounts    the demo cast's public list
//   POST /api/auth/signout          close the session
//
// The OP is never an RP of itself: the SSO/GitHub projections the
// monorepo's router computes are honestly absent here, and the signout
// has no upstream-IdP end-session leg. (The OP-side backchannel fan-out
// the signout triggers is TODO.identity-sso's wave-A tail — auth/op/
// logout.ts.)
//
// WORKER-SAFE: hono + the kernel seams only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../store'
import { getInstanceProfile } from '../profile'
import { clientInfo } from '../client-info'
import { SESSION_COOKIE, sessionCookieOpts, sessionUser } from '../session'
import { prepareBackchannelLogout } from '../auth/op/logout'

type EnvLike = Record<string, string | undefined>

/** Whether the demo-account sign-in is served on this OP deployment.
 *  The override wins; then the DEPLOYMENT PROFILE gates: an OP whose
 *  profile carries `demo_personas: false` (the production posture)
 *  serves no demo path at all. There is no SSO coupling here — the OP
 *  never configures an upstream SSO of its own. */
export function opDemoAccountsEnabled(env: EnvLike): boolean {
  const override = env.DEMO_ACCOUNTS_ENABLED?.trim().toLowerCase()
  if (override === 'true') return true
  if (override === 'false') return false
  return getInstanceProfile().demoPersonas
}

export interface AuthLeanRouterOptions {
  /** Provision the demo accounts on first request (the node posture's
   *  zero-config boot). FALSE on the Worker — provisioning there is the
   *  declared OP_ACCOUNT_SEED / the seeded preview cast, never an
   *  implicit first-request act. */
  autoSeedDemo: boolean
}

export function createAuthLeanRouter(options: AuthLeanRouterOptions): Hono {
  const auth = new Hono()

  let initialized = false
  async function ensureInit() {
    if (initialized) return
    const store = getStore()
    if (options.autoSeedDemo) await store.seedDemoAccounts()
    await store.cleanExpiredSessions()
    initialized = true
  }

  // GET /api/auth/session — check current session
  auth.get('/session', async (c) => {
    await ensureInit()
    const user = await sessionUser(c)
    if (!user) return c.json(null, 401)
    return c.json(user)
  })

  // POST /api/auth/demo — the demo-cast sign-in (the same gate as the
  // monorepo's: the deployment's demo posture decides, never the
  // caller).
  auth.post('/demo', async (c) => {
    await ensureInit()
    const env = runtimeEnv<EnvLike>(c)
    if (!opDemoAccountsEnabled(env)) {
      return c.json({ error: 'Demo accounts are disabled on this instance — sign in with single sign-on' }, 403)
    }
    const body = await c.req.json<{ email?: string; password?: string }>()
    if (!body.email || !body.password) {
      return c.json({ error: 'Email and password required' }, 400)
    }
    const user = await getStore().authenticateDemo(body.email, body.password)
    if (!user) {
      return c.json({ error: 'Invalid credentials' }, 401)
    }
    // TODO.identity-sso/02+03: the demo sign-in is a password
    // authentication event — the session's amr says so honestly (the
    // demo cast never carries factors).
    const token = await getStore().createSession(user.id, { ...clientInfo(c), amr: ['pwd'] })
    setCookie(c, SESSION_COOKIE, token, sessionCookieOpts(c))
    return c.json(user)
  })

  // GET /api/auth/demo-accounts — list available demo accounts
  auth.get('/demo-accounts', async (c) => {
    await ensureInit()
    const env = runtimeEnv<EnvLike>(c)
    if (!opDemoAccountsEnabled(env)) {
      return c.json({ enabled: false, accounts: [] })
    }
    return c.json({ enabled: true, accounts: await getStore().listDemoAccounts() })
  })

  // POST /api/auth/signout — logout. No IdP end-session leg of the OP's
  // own (the OP's sessions were never minted by an upstream IdP of this
  // service) — but TODO.identity-sso (the wave-A tail) adds the
  // OP-initiated BACKCHANNEL fan-out: the account's live-grant clients
  // with a registered backchannel receiver each get the logout_token
  // (fire-and-forget — the answer never waits on an RP). The prepare
  // rides BEFORE the delete (the grant set is the one the ending
  // presence belonged to).
  auth.post('/signout', async (c) => {
    await ensureInit()
    const token = getCookie(c, SESSION_COOKIE)
    if (token) {
      const store = getStore()
      const user = await store.getSessionUser(token)
      if (user) {
        const floatBackchannel = await prepareBackchannelLogout(c, runtimeEnv<EnvLike>(c), c.req.raw, user.id)
        await store.deleteSession(token)
        floatBackchannel()
      } else {
        await store.deleteSession(token)
      }
    }
    deleteCookie(c, SESSION_COOKIE, { path: '/' })
    return c.json({ ok: true })
  })

  return auth
}
