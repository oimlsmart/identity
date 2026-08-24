// ═══════════════════════════════════════════════════════════════════
// The factor registry's console API (TODO.identity-sso/02 passkeys +
// /03 the factor registry) — the account's OWN strong-authentication
// surface, every route session-gated and every factor named + revocable:
//
//   GET    /api/op/account/factors                      — the registry:
//                                            passkeys + TOTP apps (names,
//                                            created/last-used) + the
//                                            recovery set's honest state
//                                            (counts + age, never a hash)
//   POST   /api/op/account/factors/totp                 — start the TOTP
//                                            enrollment: the pending row,
//                                            the otpauth:// URI + the
//                                            manual-entry secret answered
//                                            ONCE (the QR renders
//                                            client-side; the secret never
//                                            leaves the page)
//   POST   /api/op/account/factors/totp/:id/verify      — the first valid
//                                            code ACTIVATES the factor
//                                            (hard-throttled: the backoff
//                                            ladder + the cap that burns
//                                            the pending enrollment)
//   DELETE /api/op/account/factors/totp/:id             — revoke the app
//   POST   /api/op/account/factors/passkeys/options     — the registration
//                                            ceremony's options (the
//                                            one-time challenge row)
//   POST   /api/op/account/factors/passkeys             — finish the
//                                            registration (the attestation
//                                            verified; the credential id
//                                            conflict is the honest 409)
//   DELETE /api/op/account/factors/passkeys/:id         — revoke the
//                                            passkey (THE GUARD: one
//                                            sign-in method always
//                                            remains — password, link, or
//                                            another passkey)
//   POST   /api/op/account/factors/recovery-codes       — regenerate the
//                                            recovery set (the old set
//                                            dies; the plaintext answers
//                                            once; the audit event lands)
//
// THE GATES (the 03 spec's posture, per wave E's live lifecycle state):
// enrollment and the recovery regenerate require a VERIFIED primary
// address (emailVerifiedAt) — the lost-device path rides the mailbox, so
// an unverified mailbox refuses factors honestly, with the reason named.
//
// Every enrollment/revocation/regeneration writes its audit event. The
// console reads the registry through this API — never a cache.
//
// WORKER-SAFE: hono + the store seam + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { clientInfo } from '@oimlsmart/platform-server/client-info'
import { sessionUser } from '@oimlsmart/platform-server/session'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { opRandomToken } from '../auth/op/keys'
import { generateTotpSecret, otpauthUri, verifyTotp } from '../auth/op/totp'
import { generateRecoveryCodes, hashRecoveryCode } from '../auth/op/recovery'
import { verifyRegistration, CeremonyError } from '../auth/op/webauthn'
import {
  auditFactor,
  factorCounts,
  MFA_FAILURE_CAP,
  recoveryCodesAtFirstFactor,
  resolveMfaBackoffBaseMs,
  throttleState,
  TOTP_ENROLL_TTL_MS,
  WEBAUTHN_CHALLENGE_TTL_MS,
} from '../auth/op/factors'
import { base64urlEncode } from '../auth/op/webauthn'

type EnvLike = Record<string, string | undefined>

/** The ceremony's binding to THIS service: the RP ID is the issuer's
 *  host EXACTLY, the expected origin the issuer EXACTLY (the 02 spec:
 *  no suffix matching, ever). */
export function webauthnBindingFor(c: Context): { rpId: string; origin: string; rpName: string } {
  const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
  const url = new URL(issuer)
  return { rpId: url.hostname, origin: url.origin, rpName: getInstanceProfile().branding.name || url.hostname }
}

export function createOpFactorsRouter(): Hono {
  const factors = new Hono()

  // The profile gate (the op-accounts posture: one build, the identity
  // module decides).
  factors.use('/api/op/account/factors*', async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  })

  /** The session + the enrollment gate. Every factors route requires the
   *  signed-in account; the MUTATIONS also require the verified primary
   *  address (the recovery floor rides the mailbox). */
  async function requireUser(c: Context) {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    return { user, error: null }
  }

  function requireVerified(c: Context, user: { emailVerifiedAt?: string | null }): Response | null {
    if (!user.emailVerifiedAt) {
      return c.json({
        error: 'Your primary email address is not verified yet. The recovery path for these factors rides that mailbox, so factors unlock once the address is verified — open your account page’s profile section for the verification state.',
      }, 403)
    }
    return null
  }

  const NAME_BOUNDS = { min: 1, max: 60 }
  function readName(raw: unknown): string | null {
    if (typeof raw !== 'string') return null
    const name = raw.trim()
    return name.length >= NAME_BOUNDS.min && name.length <= NAME_BOUNDS.max ? name : null
  }

  // GET /api/op/account/factors — the registry's console read.
  factors.get('/api/op/account/factors', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const store = getStore()
    const [passkeys, totp, recovery] = await Promise.all([
      store.listWebauthnCredentials(user.id),
      store.listTotpSecrets(user.id),
      store.recoveryCodeState(user.id),
    ])
    return c.json({
      passkeys: passkeys.map(p => ({
        credentialId: p.credentialId,
        name: p.name,
        createdAt: p.createdAt,
        lastUsedAt: p.lastUsedAt,
        // The registration's DECLARED hints (attestation 'none') — the
        // console shows them as such, never as a proof of the device.
        aaguid: p.aaguid,
        transports: p.transports,
      })),
      totp: totp.filter(t => t.verifiedAt !== null).map(t => ({
        id: t.id,
        name: t.name,
        createdAt: t.createdAt,
        lastUsedAt: t.lastUsedAt,
      })),
      // A PENDING TOTP enrollment rides along so a reloaded console can
      // finish or abandon it (the secret is NEVER re-answered).
      pendingTotp: totp.filter(t => t.verifiedAt === null).map(t => ({ id: t.id, createdAt: t.createdAt })),
      recoveryCodes: recovery,
    })
  })

  // ── the TOTP authenticator apps ─────────────────────────────────────

  // POST /api/op/account/factors/totp — start the enrollment: the pending
  // row + the otpauth:// URI + the manual secret, answered ONCE.
  factors.post('/api/op/account/factors/totp', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const refused = requireVerified(c, user)
    if (refused) return refused
    const store = getStore()
    const id = crypto.randomUUID()
    const secret = generateTotpSecret()
    const binding = webauthnBindingFor(c) // the issuer name only
    await store.createTotpSecret({ id, userId: user.id, name: 'Authenticator app (setup pending)', secret })
    return c.json({
      id,
      secret,
      otpauthUri: otpauthUri({ issuer: binding.rpName, accountName: user.email, secret }),
      expiresInMs: TOTP_ENROLL_TTL_MS,
    }, 201)
  })

  // POST /api/op/account/factors/totp/:id/verify — the first valid code
  // activates the factor. THE HARD THROTTLE: the backoff ladder rides the
  // pending row; the cap burns the enrollment (the audit carries every
  // failure). The first factor's enrollment lands the recovery set.
  factors.post('/api/op/account/factors/totp/:id/verify', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const body = await c.req.json<{ code?: string; name?: string }>().catch(() => null)
    const code = typeof body?.code === 'string' ? body.code.trim() : ''
    if (!/^\d{6}$/.test(code)) {
      return c.json({ error: 'The code is the authenticator’s current six digits.' }, 400)
    }
    const store = getStore()
    const row = await store.getTotpSecret(c.req.param('id'))
    if (!row || row.userId !== user.id) return c.json({ error: 'no such enrollment' }, 404)
    if (row.verifiedAt) return c.json({ error: 'This authenticator is already active.' }, 409)
    if (new Date(row.createdAt).getTime() + TOTP_ENROLL_TTL_MS <= Date.now()) {
      await store.deleteTotpSecret(user.id, row.id)
      await auditFactor('factor.totp_enroll_expired', user.id, { userId: user.id, userName: user.name }, {})
      return c.json({ error: 'This setup expired (10 minutes). Start it again — a fresh QR follows.' }, 410)
    }
    const throttle = throttleState(row, resolveMfaBackoffBaseMs(runtimeEnv<EnvLike>(c)).baseMs)
    if (throttle.spent) {
      await store.deleteTotpSecret(user.id, row.id)
      await auditFactor('factor.totp_enroll_locked', user.id, { userId: user.id, userName: user.name }, { failures: row.failCount })
      return c.json({ error: `Too many wrong codes — this setup was discarded. Start the enrollment again.`, locked: true }, 429)
    }
    if (throttle.waitMs > 0) {
      c.header('Retry-After', String(Math.ceil(throttle.waitMs / 1000)))
      return c.json({ error: 'Too many attempts — wait a moment before the next code.', retryAfterMs: throttle.waitMs }, 429)
    }
    if (!(await verifyTotp(row.secret, code))) {
      const failures = await store.recordTotpEnrollFailure(row.id, user.id)
      await auditFactor('factor.totp_enroll_failed', user.id, { userId: user.id, userName: user.name }, { failures })
      const locked = failures >= MFA_FAILURE_CAP
      if (locked) {
        await store.deleteTotpSecret(user.id, row.id)
        await auditFactor('factor.totp_enroll_locked', user.id, { userId: user.id, userName: user.name }, { failures })
      }
      return c.json({
        error: locked
          ? 'Too many wrong codes — this setup was discarded. Start the enrollment again.'
          : 'That code did not match. Check the authenticator’s clock and try the current code.',
        ...(locked ? { locked: true } : {}),
      }, locked ? 429 : 401)
    }
    const name = readName(body?.name) ?? 'Authenticator app'
    await store.markTotpSecretVerified(row.id, user.id, name)
    await auditFactor('factor.totp_enrolled', user.id, { userId: user.id, userName: user.name }, { name })
    // The first factor lands the recovery floor (shown once).
    const recoveryCodes = await recoveryCodesAtFirstFactor(store, user.id)
    if (recoveryCodes) {
      await auditFactor('factor.recovery_generated', user.id, { userId: user.id, userName: user.name }, { count: recoveryCodes.length })
    }
    return c.json({ ok: true, name, recoveryCodes })
  })

  // DELETE /api/op/account/factors/totp/:id — revoke the app.
  factors.delete('/api/op/account/factors/totp/:id', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const store = getStore()
    const row = await store.getTotpSecret(c.req.param('id'))
    if (!row || row.userId !== user.id) return c.json({ error: 'no such authenticator' }, 404)
    await store.deleteTotpSecret(user.id, row.id)
    await auditFactor('factor.totp_revoked', user.id, { userId: user.id, userName: user.name }, { name: row.name })
    return c.json({ ok: true })
  })

  // ── the passkeys ────────────────────────────────────────────────────

  // POST /api/op/account/factors/passkeys/options — the registration
  // ceremony's options: the one-time challenge row (the database is the
  // proof), the RP bound to THIS service exactly, the userHandle the
  // account's sub, discoverable credentials (the passwordless posture),
  // attestation 'none', the algorithm allowlist.
  factors.post('/api/op/account/factors/passkeys/options', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const refused = requireVerified(c, user)
    if (refused) return refused
    const store = getStore()
    const binding = webauthnBindingFor(c)
    const challenge = opRandomToken()
    await store.createWebauthnChallenge({ challenge, userId: user.id, kind: 'register', ttlMs: WEBAUTHN_CHALLENGE_TTL_MS })
    const existing = await store.listWebauthnCredentials(user.id)
    return c.json({
      publicKey: {
        challenge,
        rp: { id: binding.rpId, name: binding.rpName },
        user: {
          id: base64urlEncode(new TextEncoder().encode(user.id)),
          name: user.email,
          displayName: user.name,
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },   // ES256
          { type: 'public-key', alg: -8 },   // Ed25519
          { type: 'public-key', alg: -257 }, // RS256 (the Windows Hello class)
        ],
        attestation: 'none',
        authenticatorSelection: {
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'preferred',
        },
        excludeCredentials: existing.map(p => ({ type: 'public-key', id: p.credentialId })),
        timeout: WEBAUTHN_CHALLENGE_TTL_MS,
      },
    })
  })

  // POST /api/op/account/factors/passkeys — finish the registration:
  // consume the one-time challenge, verify the attestation, store the
  // credential (the id conflict is the honest 409). The first factor
  // lands the recovery set (answered once).
  factors.post('/api/op/account/factors/passkeys', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const refused = requireVerified(c, user)
    if (refused) return refused
    const body = await c.req.json<{
      name?: string
      credential?: { id?: string; response?: { clientDataJSON?: string; attestationObject?: string } }
      transports?: unknown
    }>().catch(() => null)
    const name = readName(body?.name)
    if (!name) return c.json({ error: `The passkey needs a name (1–${NAME_BOUNDS.max} characters) — "MacBook Touch ID", "Pixel", "YubiKey 5".` }, 400)
    const credential = body?.credential
    if (!credential?.id || !credential.response?.clientDataJSON || !credential.response?.attestationObject) {
      return c.json({ error: 'the credential carries its id + response (clientDataJSON, attestationObject)' }, 400)
    }
    const store = getStore()
    // The challenge: consume atomically FIRST (one-time means one-time —
    // whatever fails below never gives the ceremony a second life). The
    // clientData's own challenge field is then judged against the row.
    let clientChallenge: string
    try {
      const parsed = JSON.parse(new TextDecoder().decode(
        Uint8Array.from(atob(credential.response.clientDataJSON.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0)),
      )) as { challenge?: unknown }
      if (typeof parsed.challenge !== 'string') return c.json({ error: 'clientDataJSON carries no challenge' }, 400)
      clientChallenge = parsed.challenge
    } catch {
      return c.json({ error: 'clientDataJSON is not valid base64url JSON' }, 400)
    }
    const row = await store.consumeWebauthnChallenge(clientChallenge)
    if (!row || row.kind !== 'register' || row.userId !== user.id) {
      return c.json({ error: 'the ceremony challenge is unknown, expired, or already used — start the registration again' }, 400)
    }
    const binding = webauthnBindingFor(c)
    let registration
    try {
      registration = await verifyRegistration(
        { clientDataJSON: credential.response.clientDataJSON, attestationObject: credential.response.attestationObject },
        credential.id,
        { challenge: clientChallenge, origin: binding.origin, rpId: binding.rpId },
      )
    } catch (e) {
      if (e instanceof CeremonyError) return c.json({ error: `the authenticator’s answer did not verify: ${e.message}` }, 400)
      throw e
    }
    const transports = Array.isArray(body?.transports)
      ? body!.transports.filter((t): t is string => typeof t === 'string' && t.length <= 32).slice(0, 8)
      : []
    const created = await store.createWebauthnCredential({
      credentialId: registration.credentialId,
      userId: user.id,
      name,
      publicKeyCose: registration.publicKeyCose,
      signCount: registration.signCount,
      aaguid: registration.aaguid,
      transports,
      ip: clientInfo(c).ip,
    })
    if (!created) {
      return c.json({ error: 'this authenticator is already registered (to this or another account) — remove it there first' }, 409)
    }
    await auditFactor('factor.passkey_enrolled', user.id, { userId: user.id, userName: user.name }, {
      name, credentialId: registration.credentialId, aaguid: registration.aaguid, transports,
    })
    const recoveryCodes = await recoveryCodesAtFirstFactor(store, user.id)
    if (recoveryCodes) {
      await auditFactor('factor.recovery_generated', user.id, { userId: user.id, userName: user.name }, { count: recoveryCodes.length })
    }
    return c.json({
      ok: true,
      credential: {
        credentialId: created.credentialId,
        name: created.name,
        createdAt: created.createdAt,
        aaguid: created.aaguid,
        transports: created.transports,
      },
      recoveryCodes,
    }, 201)
  })

  // DELETE /api/op/account/factors/passkeys/:id — revoke. THE GUARD: an
  // account always keeps one way in — revoking the last passkey while no
  // password is set and no upstream is linked would strand the account,
  // so the route refuses and explains (the email reset stands behind
  // everything regardless: never a lockout).
  factors.delete('/api/op/account/factors/passkeys/:id', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const store = getStore()
    const cred = await store.getWebauthnCredential(c.req.param('id'))
    if (!cred || cred.userId !== user.id) return c.json({ error: 'no such passkey' }, 404)
    const methods = await store.countSignInMethods(user.id)
    if (methods.passkeys === 1 && !methods.password && methods.links === 0) {
      return c.json({
        error: 'This passkey is your only way to sign in. Set a password or link an upstream identity first — an account always keeps at least one sign-in method.',
      }, 409)
    }
    await store.deleteWebauthnCredential(user.id, cred.credentialId)
    await auditFactor('factor.passkey_revoked', user.id, { userId: user.id, userName: user.name }, { name: cred.name, credentialId: cred.credentialId })
    return c.json({ ok: true })
  })

  // ── the recovery codes ─────────────────────────────────────────────

  // POST /api/op/account/factors/recovery-codes — regenerate the set:
  // the old batch dies, the new plaintext answers ONCE. Requires a live
  // factor (a recovery set with nothing to recover would be a second
  // password — refused honestly).
  factors.post('/api/op/account/factors/recovery-codes', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const refused = requireVerified(c, user)
    if (refused) return refused
    const store = getStore()
    const counts = await factorCounts(store, user.id)
    if (counts.passkeys + counts.totp === 0) {
      return c.json({ error: 'Recovery codes arrive with your first factor — add a passkey or an authenticator app first.' }, 409)
    }
    const prior = await store.recoveryCodeState(user.id)
    const codes = generateRecoveryCodes()
    const hashes = await Promise.all(codes.map(hashRecoveryCode))
    await store.replaceRecoveryCodes(user.id, crypto.randomUUID(), hashes)
    await auditFactor(
      prior.total > 0 ? 'factor.recovery_regenerated' : 'factor.recovery_generated',
      user.id, { userId: user.id, userName: user.name },
      { count: codes.length, replaced: prior.total },
    )
    return c.json({ ok: true, codes })
  })

  return factors
}
