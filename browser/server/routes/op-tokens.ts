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
//   GET    /api/op/account/tokens/catalog    — the mint picker's catalog
//                                              projection (TODO.openapi/
//                                              03): the TARGET INSTANCE's
//                                              served permissions catalog
//                                              for one scoped service,
//                                              fetched server-side;
//   POST   /api/op/account/tokens            — the mint: the name + the
//                                              scope picker + the
//                                              expiration picker → the
//                                              plaintext ONCE (the GitHub
//                                              doctrine — the store holds
//                                              the SHA-256 only), the
//                                              audit event, the
//                                              notification email; the
//                                              OPTIONAL permissions set
//                                              validates against the
//                                              instance's served catalog
//                                              (fail closed);
//   PATCH  /api/op/account/tokens/:id        — the management act
//                                              (issue #115): the rename
//                                              and/or the scope edit
//                                              (the live narrowing
//                                              bound; the direction
//                                              audited + mailed) and/or
//                                              the permissions edit
//                                              (TODO.openapi/03 — the
//                                              same doctrine, adding a
//                                              permission gates on fresh
//                                              auth).
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
import { getStore, normalizePatScopes, type OrgContextResolution } from '../store'
import { getInstanceProfile } from '../profile'
import { sessionUser } from '../session'
import { emitWebhookEvent } from '../webhooks/deliver'
import { requireFreshAuth } from '../auth/op/step-up'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import {
  fetchPermissionsCatalog,
  instanceBaseUrlOf,
  parsePermissionsPayload,
  validatePatPermissions,
} from '../auth/op/catalog'
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
import type { MailEnv } from '../mailer'

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

  // GET /api/op/account/tokens/catalog?service=<clientId> — the mint
  // picker's catalog projection (TODO.openapi/03): the TARGET INSTANCE's
  // served permissions catalog (its own /api/openapi.json — never a
  // copy), fetched server-side through the one source the registry
  // vouches for (the client's registered redirect-URI origin). The
  // picker (the account console AND the registry's mint-for-user form —
  // the admin session reads it the same way) renders groups →
  // checkboxes from it. Session-gated (any signed-in account — the
  // served catalog is the instance's public document; nothing
  // account-scoped rides it). Honest failures: 404 the unknown/not-an-
  // application client, 502 the unreachable or catalog-less instance.
  tokens.get('/api/op/account/tokens/catalog', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const service = (c.req.query('service') ?? '').trim()
    if (!service) return c.json({ error: 'the service parameter is required' }, 400)
    const store = getStore()
    const client = await store.getOidcClient(service)
    if (!client || client.status !== 'active') return c.json({ error: 'no such service' }, 404)
    const base = instanceBaseUrlOf(client.redirectUris)
    if (!base) return c.json({ error: `the service '${service}' registers no instance URL` }, 404)
    const result = await fetchPermissionsCatalog(base)
    if (!result.ok) {
      return c.json({ error: `the instance at ${base} does not answer with a permissions catalog (${result.reason})` }, 502)
    }
    return c.json({ service, baseUrl: base, catalog: result.catalog })
  })

  // POST /api/op/account/tokens — the mint. The plaintext answers ONCE
  // (this response), never stores, never re-answers.
  tokens.post('/api/op/account/tokens', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const body = await c.req.json<{ name?: unknown; scopes?: unknown; expiresInDays?: unknown; permissions?: unknown }>().catch(() => null)
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
    const permissions = parsePermissionsPayload(body?.permissions)
    if (!permissions.ok) {
      return c.json({ error: 'the permissions are an optional array of the instance\'s catalog ids (strings)' }, 400)
    }

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

    // The permissions bound (TODO.openapi/03): validated against the
    // TARGET INSTANCES' served catalogs (fail closed — a permission
    // grant is a deliberate act), then pinned verbatim.
    const permissionsVerdict = await validatePatPermissions(store, scopes.map(s => s.service), permissions.requested)
    if (!permissionsVerdict.ok) return c.json({ error: permissionsVerdict.error }, 400)

    const plaintext = mintPatSecret()
    const pat = await store.createPersonalAccessToken({
      id: crypto.randomUUID(),
      userId: user.id,
      name,
      tokenHash: await hashPat(plaintext),
      tokenPrefix: patDisplayPrefix(plaintext),
      scopes: scopes.map(s => `${s.service}:${s.action}`),
      permissions: permissionsVerdict.permissions,
      orgContext: context.orgId,
      expiresAt: expiry.expiresAt,
    })
    await auditPat('account.pat_minted', user.id, { userId: user.id, userName: user.name }, {
      pat: pat.id,
      name,
      scopes: pat.scopes,
      ...(pat.permissions.length ? { permissions: pat.permissions } : {}),
      orgContext: pat.orgContext,
      expiresAt: pat.expiresAt,
    })
    emitWebhookEvent(c, {
      event: 'account.pat_minted',
      accountId: user.id,
      data: { pat: pat.id, name, scopes: pat.scopes, orgContext: pat.orgContext, expiresAt: pat.expiresAt },
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
    emitWebhookEvent(c, {
      event: 'account.pat_revoked',
      accountId: user.id,
      data: { pat: pat.id, name: pat.name, scopes: pat.scopes },
    })
    return c.json({ ok: true })
  })

  // PATCH /api/op/account/tokens/:id — the MANAGEMENT act (issue #115):
  // the rename (presentation-only) and/or the scope edit (the complete
  // replacement set, the mint's validation exactly — the live narrowing
  // bound under the session's effective org context). Both directions
  // are safe because the exchange re-judges the narrowing against the
  // holder's live standing on every use; widening is still audited (and
  // mailed) distinctly, because widening a credential is a
  // security-relevant act an owner may wish to review.
  tokens.patch('/api/op/account/tokens/:id', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const store = getStore()
    const pat = await store.getPersonalAccessToken(c.req.param('id'))
    if (!pat || pat.userId !== user.id) return c.json({ error: 'no such token' }, 404)
    // A dead credential's permissions are not meaningfully editable.
    if (pat.revokedAt || new Date(pat.expiresAt).getTime() <= Date.now()) {
      return c.json({ error: 'this token is revoked or expired — mint a fresh one instead of editing a dead credential' }, 409)
    }
    const body = await c.req.json<{ name?: unknown; scopes?: unknown; permissions?: unknown }>().catch(() => null)
    if (!body || (body.name === undefined && body.scopes === undefined && body.permissions === undefined)) {
      return c.json({ error: 'the edit needs a name, a scopes, and/or a permissions field' }, 400)
    }
    const config = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))

    let updated = pat
    if (body.name !== undefined) {
      const name = typeof body.name === 'string' ? body.name.trim() : ''
      if (name.length < 1 || name.length > 60) {
        return c.json({ error: 'the token needs a name (1–60 characters) — the console list labels by it' }, 400)
      }
      updated = (await store.renamePersonalAccessToken(pat.id, user.id, name))!
      await auditPat('account.pat_renamed', user.id, { userId: user.id, userName: user.name }, {
        pat: pat.id,
        from: pat.name,
        to: name,
      })
      await sendOpSecurityMail(runtimeEnv<MailEnv>(c), store, {
        userId: user.id,
        template: 'pat_edited',
        issuer: config.issuer,
        params: {
          name: user.name,
          tokenName: name,
          change: 'renamed',
          scopes: pat.scopes.join(', '),
          expires: new Date(pat.expiresAt).toISOString().slice(0, 10),
        },
      })
    }

    if (body.scopes !== undefined) {
      const scopes = normalizePatScopes(body.scopes)
      if (!scopes) {
        return c.json({ error: 'the scopes are the PAT grammar: a non-empty list of \'<service>:<read|write|admin>\'' }, 400)
      }
      // THE NARROWING BOUND, at edit (as at mint — the exchange
      // re-judges it live): the session's resolved context IS the
      // token's ceiling.
      const context: OrgContextResolution = {
        orgId: user.orgId ?? null,
        roles: user.roles?.length ? user.roles : [user.role],
        cone: user.cone ?? null,
      }
      const verdict = await resolvePatScopesForAccount(store, user, context, scopes, runtimeEnv<EnvLike>(c))
      if (!verdict.ok) return c.json({ error: verdict.error }, 403)
      const nextScopes = scopes.map(s => `${s.service}:${s.action}`)
      const added = nextScopes.filter(s => !updated.scopes.includes(s))
      const removed = updated.scopes.filter(s => !nextScopes.includes(s))
      // The DIRECTION rides the CLASS RANKS, not the literal string
      // diffs: the action classes nest within a service (admin >
      // write > read — the fold's own rule), so write→read is a
      // NARROWING whose literal diff would read 'added: read'.
      // Widening wins a genuinely mixed edit (the security-relevant
      // reading an owner reviews).
      const classRank = (cls: string) => (cls === 'admin' ? 3 : cls === 'write' ? 2 : 1)
      const oldRanks = new Map(updated.scopes.map(s => { const [svc, cls] = s.split(':'); return [svc, classRank(cls)] }))
      const newRanks = new Map(nextScopes.map(s => { const [svc, cls] = s.split(':'); return [svc, classRank(cls)] }))
      let widenedAny = false
      for (const svc of new Set([...oldRanks.keys(), ...newRanks.keys()])) {
        if ((newRanks.get(svc) ?? 0) > (oldRanks.get(svc) ?? 0)) widenedAny = true
      }
      // The freshness gate (TODO.modern/06's open half): a WIDENING
      // edit is a bank-grade act — a stale session refuses with the
      // distinct fresh_auth_required shape (narrow/rename never gated).
      if (widenedAny) {
        const stale = await requireFreshAuth(c)
        if (stale) return stale
      }
      if (added.length || removed.length) {
        updated = (await store.updatePersonalAccessTokenScopes(pat.id, user.id, nextScopes))!
        const action = widenedAny ? 'account.pat_scopes_widened' : 'account.pat_scopes_narrowed'
        await auditPat(action, user.id, { userId: user.id, userName: user.name }, {
          pat: pat.id,
          name: updated.name,
          added,
          removed,
          scopes: nextScopes,
        })
        await sendOpSecurityMail(runtimeEnv<MailEnv>(c), store, {
          userId: user.id,
          template: 'pat_edited',
          issuer: config.issuer,
          params: {
            name: user.name,
            tokenName: updated.name,
            change: added.length ? 'widened' : 'narrowed',
            scopes: nextScopes.join(', '),
            expires: new Date(pat.expiresAt).toISOString().slice(0, 10),
          },
        })
      }
    }

    if (body.permissions !== undefined) {
      const parsed = parsePermissionsPayload(body.permissions)
      if (!parsed.ok) {
        return c.json({ error: 'the permissions are an array of the instance\'s catalog ids (strings; [] clears the set)' }, 400)
      }
      // The validation targets the token's EFFECTIVE scope set: the
      // scopes act above has already applied its replacement (when this
      // edit carried one), so the row in `updated` pins it — a
      // permission must always sit inside a service the token can
      // actually reach.
      const effectiveServices = (normalizePatScopes(updated.scopes) ?? []).map(s => s.service)
      const permissionsVerdict = await validatePatPermissions(store, effectiveServices, parsed.requested)
      if (!permissionsVerdict.ok) return c.json({ error: permissionsVerdict.error }, 400)
      const nextPermissions = permissionsVerdict.permissions
      const addedPerms = nextPermissions.filter(p => !updated.permissions.includes(p))
      const removedPerms = updated.permissions.filter(p => !nextPermissions.includes(p))
      if (addedPerms.length || removedPerms.length) {
        // The widening-sensitive act (the scope edit's doctrine): ADDING
        // a catalog permission widens what the instance will let the
        // token do — a stale session refuses with the distinct
        // fresh_auth_required shape; a removal-only edit never gates.
        if (addedPerms.length) {
          const stale = await requireFreshAuth(c)
          if (stale) return stale
        }
        updated = (await store.updatePersonalAccessTokenPermissions(pat.id, user.id, nextPermissions))!
        const action = addedPerms.length ? 'account.pat_permissions_widened' : 'account.pat_permissions_narrowed'
        await auditPat(action, user.id, { userId: user.id, userName: user.name }, {
          pat: pat.id,
          name: updated.name,
          added: addedPerms,
          removed: removedPerms,
          permissions: nextPermissions,
        })
        await sendOpSecurityMail(runtimeEnv<MailEnv>(c), store, {
          userId: user.id,
          template: 'pat_edited',
          issuer: config.issuer,
          params: {
            name: user.name,
            tokenName: updated.name,
            change: addedPerms.length ? 'widened' : 'narrowed',
            scopes: updated.scopes.join(', '),
            expires: new Date(pat.expiresAt).toISOString().slice(0, 10),
          },
        })
      }
    }

    return c.json({ token: patListRow(updated) })
  })

  return tokens
}
