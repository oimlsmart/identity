// ═══════════════════════════════════════════════════════════════════
// The sign-in's second-factor + passwordless half (TODO.identity-sso/02
// + /03) — the choreography after the password verifies (POST
// /api/op/login's mfaRequired branch) and the passkey-primary path:
//
//   POST /api/op/login/mfa/totp             — the authenticator code
//   POST /api/op/login/mfa/recovery         — a recovery code (one-time)
//   POST /api/op/login/mfa/passkey/options  — the second-factor assertion
//                                             ceremony (the account's
//                                             credentials only)
//   POST /api/op/login/mfa/passkey          — the passkey assertion
//   POST /api/op/login/passkey/options      — the PASSWORDLESS ceremony
//                                             (discoverable credentials;
//                                             nothing account-specific is
//                                             ever revealed)
//   POST /api/op/login/passkey              — the passwordless finish
//
// THE HARD RULES (the 03 spec):
//   - the pending row is one-time + short-TTL (the database is the
//     proof), consumed atomically at completion — a concurrent
//     completion loses;
//   - the verification endpoints throttle HARD: the per-account backoff
//     ladder rides the row (fail_count + last_failure_at), every failure
//     audits, and the cap burns the attempt + emails the account (the
//     locked-out burst surfaces — and the admin dashboard's security
//     signals read the same audit chain);
//   - the passkey ceremonies re-check the exact origin + RP ID, and the
//     signature counter's REGRESSION is the clone signal (fail + audit);
//   - never SMS (the documented refusal — SIM-swap and interception).
//
// The session the completion mints carries the amr provenance (['pwd',
// 'otp'] / ['pwd', 'webauthn', …] / ['webauthn', …] / ['pwd',
// 'recovery']) — the ID token later carries the same list.
//
// WORKER-SAFE: hono + the store seam + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { setCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { clientInfo } from '@oimlsmart/platform-server/client-info'
import { SESSION_COOKIE, sessionCookieOpts } from '@oimlsmart/platform-server/session'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { opRandomToken } from '../auth/op/keys'
import { verifyTotp } from '../auth/op/totp'
import { hashRecoveryCode, recoveryCodePlausible } from '../auth/op/recovery'
import { verifyAssertion, CeremonyError } from '../auth/op/webauthn'
import { webauthnBindingFor } from './op-factors'
import { sendOpMail } from '../auth/op/mail'
import type { MailEnv } from '@oimlsmart/platform-server/mailer'
import {
  auditFactor,
  MFA_FAILURE_CAP,
  MFA_PENDING_TTL_MS,
  passkeyAmr,
  resolveMfaBackoffBaseMs,
  throttleState,
  WEBAUTHN_CHALLENGE_TTL_MS,
} from '../auth/op/factors'
import type { MfaPending, WebauthnCredential } from '@oimlsmart/platform-server/store'

type EnvLike = Record<string, string | undefined>

export function createOpMfaRouter(): Hono {
  const mfa = new Hono()

  // The profile gate (the op-accounts posture).
  mfa.use('/api/op/login/*', async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  })

  /** The lockout email: the burned attempt surfaces to the account
   *  (never blocking the path — the mailer doctrine). */
  async function notifyMfaLocked(c: Context, userId: string): Promise<void> {
    const account = await getStore().getUserById(userId)
    if (!account) return
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    await sendOpMail(runtimeEnv<MailEnv>(c), {
      to: account.email,
      template: 'mfa_locked',
      issuer,
      params: { name: account.name, when: new Date().toISOString().slice(0, 16).replace('T', ' ') },
    })
  }

  /** The new-sign-in notification (the op-accounts posture: every entry
   *  tells the account holder; never blocks the path). */
  async function notifySignIn(c: Context, userId: string, methodKey: string): Promise<void> {
    const account = await getStore().getUserById(userId)
    if (!account) return
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    await sendOpMail(runtimeEnv<MailEnv>(c), {
      to: account.email,
      template: 'signin',
      issuer,
      params: { name: account.name, when: new Date().toISOString().slice(0, 16).replace('T', ' '), method: methodKey },
    })
  }

  /** The completion: consume the pending row ATOMICALLY (a concurrent
   *  completion loses), mint the session with the full amr provenance,
   *  set the cookie, audit the sign-in, notify. Answers null when the
   *  race was lost. */
  async function completeSignIn(c: Context, pendingToken: string, addedAmr: string[], methodKey: string, auditMethod: string) {
    const store = getStore()
    const pending = await store.consumeMfaPending(pendingToken)
    if (!pending) return null
    const amr = [...pending.amr]
    for (const a of addedAmr) if (!amr.includes(a)) amr.push(a)
    await store.touchLastLogin(pending.userId)
    const token = await store.createSession(pending.userId, { ...clientInfo(c), amr })
    setCookie(c, SESSION_COOKIE, token, sessionCookieOpts(c))
    await auditFactor('account.sign_in', pending.userId, { userId: pending.userId }, { method: auditMethod, amr })
    await notifySignIn(c, pending.userId, methodKey)
    return { userId: pending.userId, amr }
  }

  /** The pending row's guards for a verify attempt: present, live, and
   *  the throttle ladder's state. Answers { pending } or the response. */
  async function pendingFor(c: Context, token: string): Promise<{ pending: MfaPending; error: null } | { pending: null; error: Response }> {
    const pending = await getStore().getMfaPending(token)
    if (!pending || pending.consumedAt || new Date(pending.expiresAt).getTime() <= Date.now()) {
      return { pending: null, error: c.json({ error: 'This sign-in challenge expired or was already completed. Sign in again.' }, 401) }
    }
    const throttle = throttleState(pending, resolveMfaBackoffBaseMs(runtimeEnv<EnvLike>(c)).baseMs)
    if (throttle.spent) {
      await getStore().consumeMfaPending(token) // burned, honestly
      await auditFactor('factor.mfa_locked', pending.userId, { userId: pending.userId }, { failures: pending.failCount })
      await notifyMfaLocked(c, pending.userId)
      return { pending: null, error: c.json({ error: 'Too many failed attempts — this sign-in was closed. Sign in again; your account was notified by email.', locked: true }, 429) }
    }
    if (throttle.waitMs > 0) {
      c.header('Retry-After', String(Math.ceil(throttle.waitMs / 1000)))
      return { pending: null, error: c.json({ error: 'Too many attempts — wait a moment before the next try.', retryAfterMs: throttle.waitMs }, 429) }
    }
    return { pending, error: null }
  }

  /** A failed verify: the ladder step, the audit, the cap's burn + the
   *  account's lockout email. */
  async function failAttempt(c: Context, pending: MfaPending, kind: 'totp' | 'recovery' | 'passkey', errorText: string): Promise<Response> {
    const fresh = await getStore().recordMfaPendingFailure(pending.token)
    const failures = fresh?.failCount ?? pending.failCount + 1
    await auditFactor('factor.mfa_failed', pending.userId, { userId: pending.userId }, { kind, failures })
    if (failures >= MFA_FAILURE_CAP) {
      await getStore().consumeMfaPending(pending.token)
      await auditFactor('factor.mfa_locked', pending.userId, { userId: pending.userId }, { failures })
      await notifyMfaLocked(c, pending.userId)
      return c.json({ error: 'Too many failed attempts — this sign-in was closed. Sign in again; your account was notified by email.', locked: true }, 429)
    }
    return c.json({ error: errorText }, 401)
  }

  // POST /api/op/login/mfa/totp — the authenticator code. Any VERIFIED
  // app on the account may answer (the registry allows several).
  mfa.post('/api/op/login/mfa/totp', async (c) => {
    const body = await c.req.json<{ token?: string; code?: string }>().catch(() => null)
    const code = typeof body?.code === 'string' ? body.code.trim() : ''
    if (typeof body?.token !== 'string' || !body.token || !/^\d{6}$/.test(code)) {
      return c.json({ error: 'The challenge token and the six-digit code are required.' }, 400)
    }
    const { pending, error } = await pendingFor(c, body.token)
    if (error || !pending) return error!
    const store = getStore()
    const secrets = (await store.listTotpSecrets(pending.userId)).filter(t => t.verifiedAt !== null)
    for (const secret of secrets) {
      if (await verifyTotp(secret.secret, code)) {
        await store.markTotpSecretUsed(secret.id, clientInfo(c))
        const done = await completeSignIn(c, pending.token, ['otp'], 'mail.signin.methodPasswordTotp', 'password+totp')
        if (!done) return c.json({ error: 'This sign-in challenge expired or was already completed. Sign in again.' }, 401)
        return c.json(await store.getUserById(done.userId))
      }
    }
    return failAttempt(c, pending, 'totp', 'That code did not match. Use the authenticator’s current code.')
  })

  // POST /api/op/login/mfa/recovery — a recovery code: one-time, hashed,
  // the account-recovery floor (never the only path — the email reset
  // stands behind everything).
  mfa.post('/api/op/login/mfa/recovery', async (c) => {
    const body = await c.req.json<{ token?: string; code?: string }>().catch(() => null)
    const code = typeof body?.code === 'string' ? body.code.trim() : ''
    if (typeof body?.token !== 'string' || !body.token || !recoveryCodePlausible(code)) {
      return c.json({ error: 'The challenge token and a recovery code are required.' }, 400)
    }
    const { pending, error } = await pendingFor(c, body.token)
    if (error || !pending) return error!
    const store = getStore()
    const consumed = await store.consumeRecoveryCode(pending.userId, await hashRecoveryCode(code))
    if (consumed) {
      await auditFactor('factor.recovery_used', pending.userId, { userId: pending.userId }, {})
      const done = await completeSignIn(c, pending.token, ['recovery'], 'mail.signin.methodPasswordRecovery', 'password+recovery')
      if (!done) return c.json({ error: 'This sign-in challenge expired or was already completed. Sign in again.' }, 401)
      return c.json(await store.getUserById(done.userId))
    }
    return failAttempt(c, pending, 'recovery', 'That recovery code is not valid (or was already used).')
  })

  // POST /api/op/login/mfa/passkey/options — the second-factor ceremony:
  // the account's credentials only, the challenge bound to the account.
  mfa.post('/api/op/login/mfa/passkey/options', async (c) => {
    const body = await c.req.json<{ token?: string }>().catch(() => null)
    if (typeof body?.token !== 'string' || !body.token) return c.json({ error: 'The challenge token is required.' }, 400)
    const { pending, error } = await pendingFor(c, body.token)
    if (error || !pending) return error!
    const store = getStore()
    const credentials = await store.listWebauthnCredentials(pending.userId)
    if (credentials.length === 0) return c.json({ error: 'This account holds no passkey.' }, 404)
    const binding = webauthnBindingFor(c)
    const challenge = opRandomToken()
    await store.createWebauthnChallenge({ challenge, userId: pending.userId, kind: 'assert', ttlMs: WEBAUTHN_CHALLENGE_TTL_MS })
    return c.json({
      publicKey: {
        challenge,
        rpId: binding.rpId,
        allowCredentials: credentials.map(p => ({ type: 'public-key', id: p.credentialId, transports: p.transports.length ? p.transports : undefined })),
        userVerification: 'preferred',
        timeout: WEBAUTHN_CHALLENGE_TTL_MS,
      },
    })
  })

  /** The assertion ceremony's shared verification: the challenge's
   *  one-time row, the credential's resolution + ownership, the
   *  signature, the counter's clone guard. Answers { cred } on success;
   *  { error } carries the refusal. The CLONE refusal rides `clone: true`
   *  so the caller answers it directly (already audited — it is a
   *  security signal, never a throttle-ladder failure). */
  async function verifyAssertionFor(
    c: Context,
    credential: { id?: string; response?: { clientDataJSON?: string; authenticatorData?: string; signature?: string; userHandle?: string | null } } | undefined,
    expectedUserId: string | null,
  ): Promise<{ cred: WebauthnCredential; signCount: number; error: null; clone?: never } | { cred: null; signCount: 0; error: Response; clone?: boolean }> {
    if (!credential?.id || !credential.response?.clientDataJSON || !credential.response?.authenticatorData || !credential.response?.signature) {
      return { cred: null, signCount: 0, error: c.json({ error: 'the assertion carries its id + response (clientDataJSON, authenticatorData, signature)' }, 400) }
    }
    // The challenge the authenticator answered IS the one-time row's key.
    let clientChallenge: string
    try {
      const parsed = JSON.parse(new TextDecoder().decode(
        Uint8Array.from(atob(credential.response.clientDataJSON.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0)),
      )) as { challenge?: unknown }
      if (typeof parsed.challenge !== 'string') return { cred: null, signCount: 0, error: c.json({ error: 'clientDataJSON carries no challenge' }, 400) }
      clientChallenge = parsed.challenge
    } catch {
      return { cred: null, signCount: 0, error: c.json({ error: 'clientDataJSON is not valid base64url JSON' }, 400) }
    }
    const store = getStore()
    // Consumed atomically FIRST: whatever fails below never gets the
    // challenge a second life (a replay answers the same refusal).
    const row = await store.consumeWebauthnChallenge(clientChallenge)
    if (!row || row.kind !== 'assert' || row.userId !== expectedUserId) {
      return { cred: null, signCount: 0, error: c.json({ error: 'the ceremony challenge is unknown, expired, or already used — start the sign-in again' }, 401) }
    }
    const cred = await store.getWebauthnCredential(credential.id)
    if (!cred || (expectedUserId !== null && cred.userId !== expectedUserId)) {
      return { cred: null, signCount: 0, error: c.json({ error: 'this passkey is not registered' }, 401) }
    }
    const binding = webauthnBindingFor(c)
    let assertion: { signCount: number; userVerified: boolean }
    try {
      assertion = await verifyAssertion(
        {
          clientDataJSON: credential.response.clientDataJSON,
          authenticatorData: credential.response.authenticatorData,
          signature: credential.response.signature,
        },
        cred.publicKeyCose,
        { challenge: clientChallenge, origin: binding.origin, rpId: binding.rpId },
      )
    } catch (e) {
      if (e instanceof CeremonyError) return { cred: null, signCount: 0, error: c.json({ error: `the authenticator’s answer did not verify: ${e.message}` }, 401) }
      throw e
    }
    // THE CLONE RULE: the store's guarded advance decides. A regressed
    // counter fails the assertion AND audits the clone signal.
    const advance = await store.advanceWebauthnCounter(cred.credentialId, assertion.signCount, clientInfo(c))
    if (advance !== 'ok') {
      await auditFactor('factor.clone_refused', cred.userId, { userId: cred.userId }, {
        credentialId: cred.credentialId, name: cred.name, presented: assertion.signCount,
      })
      return { cred: null, signCount: 0, clone: true, error: c.json({ error: 'this passkey’s signature counter regressed — a cloned credential is refused. Revoke it from your account page and register the authenticator again.' }, 401) }
    }
    return { cred, signCount: assertion.signCount, error: null }
  }

  // POST /api/op/login/mfa/passkey — the passkey as the second factor.
  mfa.post('/api/op/login/mfa/passkey', async (c) => {
    const body = await c.req.json<{
      token?: string
      credential?: { id?: string; response?: { clientDataJSON?: string; authenticatorData?: string; signature?: string; userHandle?: string | null } }
    }>().catch(() => null)
    if (typeof body?.token !== 'string' || !body.token) return c.json({ error: 'The challenge token is required.' }, 400)
    const { pending, error } = await pendingFor(c, body.token)
    if (error || !pending) return error!
    const { cred, error: assertionError, clone } = await verifyAssertionFor(c, body?.credential, pending.userId)
    if (clone) return assertionError! // the clone refusal stands as answered (audited inside)
    if (assertionError || !cred) return failAttempt(c, pending, 'passkey', 'The passkey assertion did not verify. Try again.')
    const done = await completeSignIn(c, pending.token, passkeyAmr(cred.transports), 'mail.signin.methodPasswordPasskey', 'password+webauthn')
    if (!done) return c.json({ error: 'This sign-in challenge expired or was already completed. Sign in again.' }, 401)
    return c.json(await getStore().getUserById(done.userId))
  })

  // ── the passwordless passkey sign-in ────────────────────────────────

  // POST /api/op/login/passkey/options — the passwordless ceremony:
  // discoverable credentials (allowCredentials EMPTY — the authenticator
  // resolves the account), the challenge unbound (the credential id
  // resolves the account at the finish). Nothing account-specific is
  // ever revealed (the answer is identical for every caller).
  mfa.post('/api/op/login/passkey/options', async (c) => {
    const binding = webauthnBindingFor(c)
    const challenge = opRandomToken()
    await getStore().createWebauthnChallenge({ challenge, userId: null, kind: 'assert', ttlMs: WEBAUTHN_CHALLENGE_TTL_MS })
    return c.json({
      publicKey: {
        challenge,
        rpId: binding.rpId,
        allowCredentials: [],
        userVerification: 'preferred',
        timeout: WEBAUTHN_CHALLENGE_TTL_MS,
      },
    })
  })

  // POST /api/op/login/passkey — the passwordless finish: the credential
  // id resolves the account; the userHandle must BE that account's sub
  // (the 02 spec's binding). amr carries ['webauthn' (+ 'hwk')] — no
  // password was presented, honestly.
  mfa.post('/api/op/login/passkey', async (c) => {
    const body = await c.req.json<{
      credential?: { id?: string; response?: { clientDataJSON?: string; authenticatorData?: string; signature?: string; userHandle?: string | null } }
    }>().catch(() => null)
    const { cred, error: assertionError } = await verifyAssertionFor(c, body?.credential, null)
    if (assertionError || !cred) return assertionError!
    // The userHandle binding: the authenticator's account claim must be
    // this credential's account (the resident credential carries it).
    const presented = body?.credential?.response?.userHandle
    const presentedId = typeof presented === 'string' && presented
      ? new TextDecoder().decode(Uint8Array.from(atob(presented.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0)))
      : null
    if (presentedId !== cred.userId) {
      await auditFactor('factor.assertion_refused', cred.userId, { userId: cred.userId }, { credentialId: cred.credentialId, reason: 'userHandle mismatch' })
      return c.json({ error: 'the assertion’s account claim does not match the credential' }, 401)
    }
    // The deactivation wall (the password sign-in's own rule).
    const account = (await getStore().listUsers()).find(u => u.id === cred.userId) ?? null
    if (!account) return c.json({ error: 'this passkey’s account no longer exists' }, 401)
    if (!account.active) {
      return c.json({ error: 'This account is deactivated — contact your administrator.' }, 403)
    }
    const store = getStore()
    const amr = passkeyAmr(cred.transports)
    await store.touchLastLogin(cred.userId)
    const token = await store.createSession(cred.userId, { ...clientInfo(c), amr })
    setCookie(c, SESSION_COOKIE, token, sessionCookieOpts(c))
    await auditFactor('account.sign_in', cred.userId, { userId: cred.userId }, { method: 'webauthn', amr })
    await notifySignIn(c, cred.userId, 'mail.signin.methodPasskey')
    return c.json(await store.getUserById(cred.userId))
  })

  return mfa
}
