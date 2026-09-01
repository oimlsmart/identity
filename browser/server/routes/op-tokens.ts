// ═══════════════════════════════════════════════════════════════════
// The developer tokens' console API (TODO.identity-features/08) — the
// account's OWN personal access tokens, every route session-gated:
//
//   GET    /api/op/account/tokens            — the registry: the account's
//                                              tokens (name, the scope
//                                              summary, the last-used
//                                              stamp, the expiration, the
//                                              state) — NEVER the
//                                              plaintext, never the hash;
//   POST   /api/op/account/tokens            — the mint: the name + the
//                                              scope picker + the
//                                              expiration picker → the
//                                              plaintext ONCE (the GitHub
//                                              doctrine — the store holds
//                                              the SHA-256 only), the
//                                              audit event, the
//                                              notification email;
//   DELETE /api/op/account/tokens/:id        — the revoke (the owner's
//                                              guarded flip; the row stays
//                                              for the audit + the org
//                                              inventory).
//
// The mint's org-context pin: the session's EFFECTIVE context (the
// account acts AS one org at a time — the token inherits exactly that
// visibility, never wider). The narrowing bound runs at mint AND at
// exchange (auth/op/tokens.ts's resolvePatScopesForAccount — the one
// computation, the store re-judged live).
//
// The mint/refuse acts land on the audit chain (entity_type 'account' —
// the account's own activity feed shows them); the mint + expiry-soon
// emails ride the OP's mailer (auth/op/mail.ts).
//
// WORKER-SAFE: hono + the store seam + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, normalizePatScopes, type OrgContextResolution } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { sessionUser } from '@oimlsmart/platform-server/session'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import {
  auditPat,
  hashPat,
  mintPatSecret,
  patDisplayPrefix,
  patListRow,
  patServicesForAccount,
  resolvePatExpiry,
  resolvePatScopesForAccount,
} from '../auth/op/tokens'
import { sendOpSecurityMail } from '../auth/op/mail'
import type { MailEnv } from '@oimlsmart/platform-server/mailer'

type EnvLike = Record<string, string | undefined>

export function createOpTokensRouter(): Hono {
  const tokens = new Hono()

  // The profile gate (the op-accounts posture: one build, the identity
  // module decides).
  tokens.use('/api/op/account/tokens*', async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  })

  async function requireUser(c: Context) {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    return { user, error: null }
  }

  // GET /api/op/account/tokens — the account's own registry + the
  // picker's catalog (the services the account may mint for, each with
  // the widest action class its standing admits).
  tokens.get('/api/op/account/tokens', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const store = getStore()
    const context: OrgContextResolution = {
      orgId: user.orgId ?? null,
      roles: user.roles?.length ? user.roles : [user.role],
      cone: user.cone ?? null,
    }
    const [rows, services] = await Promise.all([
      store.listPersonalAccessTokens(user.id),
      patServicesForAccount(store, user, context, runtimeEnv<EnvLike>(c)),
    ])
    return c.json({ tokens: rows.map(row => patListRow(row)), services })
  })

  // POST /api/op/account/tokens — the mint. The plaintext answers ONCE
  // (this response), never stores, never re-answers.
  tokens.post('/api/op/account/tokens', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const body = await c.req.json<{ name?: unknown; scopes?: unknown; expiresInDays?: unknown }>().catch(() => null)
    const name = typeof body?.name === 'string' ? body.name.trim() : ''
    if (name.length < 1 || name.length > 60) {
      return c.json({ error: 'the token needs a name (1–60 characters) — the console list labels by it' }, 400)
    }
    const scopes = normalizePatScopes(body?.scopes)
    if (!scopes) {
      return c.json({ error: 'the scopes are the PAT grammar: a non-empty list of \'<service>:<read|write|admin>\'' }, 400)
    }
    const expiry = resolvePatExpiry(body?.expiresInDays)
    if ('error' in expiry) return c.json({ error: expiry.error }, 400)

    // THE NARROWING BOUND, at mint (the exchange re-judges it live): the
    // session's resolved context IS the token's ceiling (the account acts
    // AS this org, with this role set — never wider).
    const context: OrgContextResolution = {
      orgId: user.orgId ?? null,
      roles: user.roles?.length ? user.roles : [user.role],
      cone: user.cone ?? null,
    }
    const store = getStore()
    const verdict = await resolvePatScopesForAccount(store, user, context, scopes, runtimeEnv<EnvLike>(c))
    if (!verdict.ok) return c.json({ error: verdict.error }, 403)

    const plaintext = mintPatSecret()
    const pat = await store.createPersonalAccessToken({
      id: crypto.randomUUID(),
      userId: user.id,
      name,
      tokenHash: await hashPat(plaintext),
      tokenPrefix: patDisplayPrefix(plaintext),
      scopes: scopes.map(s => `${s.service}:${s.action}`),
      orgContext: context.orgId,
      expiresAt: expiry.expiresAt,
    })
    await auditPat('account.pat_minted', user.id, { userId: user.id, userName: user.name }, {
      pat: pat.id,
      name,
      scopes: pat.scopes,
      orgContext: pat.orgContext,
      expiresAt: pat.expiresAt,
    })
    // The security notification posture: the holder learns of every mint
    // (never blocking the act — sendOpMail's honest result).
    // TODO.identity-features/01: the notice fans out to the primary PLUS
    // every verified additional (auth/op/mail.ts's sendOpSecurityMail).
    const config = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
    await sendOpSecurityMail(runtimeEnv<MailEnv>(c), getStore(), {
      userId: user.id,
      template: 'pat_minted',
      issuer: config.issuer,
      params: {
        name: user.name,
        tokenName: name,
        scopes: pat.scopes.join(', '),
        expires: new Date(pat.expiresAt).toISOString().slice(0, 10),
      },
    })
    return c.json({ token: { ...patListRow(pat), plaintext } }, 201)
  })

  // DELETE /api/op/account/tokens/:id — the revoke (the store's guard:
  // the owner's live row flips, once).
  tokens.delete('/api/op/account/tokens/:id', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const store = getStore()
    const pat = await store.getPersonalAccessToken(c.req.param('id'))
    if (!pat || pat.userId !== user.id) return c.json({ error: 'no such token' }, 404)
    const flipped = await store.revokePersonalAccessToken(pat.id, user.id, user.email)
    if (!flipped) return c.json({ error: 'this token is already revoked' }, 409)
    await auditPat('account.pat_revoked', user.id, { userId: user.id, userName: user.name }, {
      pat: pat.id,
      name: pat.name,
      scopes: pat.scopes,
    })
    return c.json({ ok: true })
  })

  return tokens
}
