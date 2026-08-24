// ═══════════════════════════════════════════════════════════════════
// The factor registry's shared ceremony helpers (TODO.identity-sso/02
// + /03) — the pieces the two routers (routes/op-factors.ts, the
// console's registry API; routes/op-mfa.ts, the sign-in's second-factor
// half) compute identically:
//
//   - the TTLs (the one-time challenges, the pending-MFA row, the TOTP
//     enrollment window);
//   - the THROTTLE LADDER (the hard rule — the six-digit window invites
//     brute force): per-account backoff riding the row's fail_count +
//     last_failure_at, the cap that burns the attempt and emails the
//     account;
//   - the first-factor recovery-code generation (the account-recovery
//     floor arrives WITH the first factor, never before — a code set
//     without a factor to recover would be a second password);
//   - the amr assembly (RFC 8176; 'hwk' rides the registration's
//     DECLARED transports — attestation is 'none', so it is an honest
//     hint, documented as such, never a hardware proof).
//
// WORKER-SAFE: the store seam + WebCrypto only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { getStore, type ServerStore } from '@oimlsmart/platform-server/store'
import { generateRecoveryCodes, hashRecoveryCode } from './recovery'

export const WEBAUTHN_CHALLENGE_TTL_MS = 5 * 60 * 1000
export const MFA_PENDING_TTL_MS = 5 * 60 * 1000
export const TOTP_ENROLL_TTL_MS = 10 * 60 * 1000

/** The verification throttle: after N failures the next attempt waits
 *  2^N × baseMs (capped at 30 s); at the cap the attempt burns. The base
 *  is the deployment's (OP_MFA_BACKOFF_BASE_MS — the OP_RATE_LIMIT_*
 *  precedent; the tests declare 1 ms so the ladder is exercised, not
 *  slept through). */
export const MFA_FAILURE_CAP = 5
export const MFA_BACKOFF_DEFAULTS = { baseMs: 1000, capMs: 30_000 }

/** Resolve the backoff tuning from the env surface (invalid values fall
 *  back honestly, the problem named — the rate-limit.ts posture). */
export function resolveMfaBackoffBaseMs(env: Record<string, string | undefined>): { baseMs: number; problems: string[] } {
  const problems: string[] = []
  let baseMs = MFA_BACKOFF_DEFAULTS.baseMs
  const raw = env.OP_MFA_BACKOFF_BASE_MS?.trim()
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw)
    if (!Number.isInteger(parsed) || parsed <= 0) {
      problems.push(`OP_MFA_BACKOFF_BASE_MS is not a positive integer: ${JSON.stringify(raw)} — the default ${MFA_BACKOFF_DEFAULTS.baseMs} applies`)
    } else {
      baseMs = parsed
    }
  }
  return { baseMs, problems }
}

export function mfaBackoffMs(failCount: number, baseMs: number = MFA_BACKOFF_DEFAULTS.baseMs): number {
  if (failCount <= 0) return 0
  return Math.min(2 ** failCount * baseMs, MFA_BACKOFF_DEFAULTS.capMs)
}

/** The row's current throttle state: the wait still owed (0 = an attempt
 *  may be judged now), and whether the ladder is spent. */
export function throttleState(row: { failCount: number; lastFailureAt: string | null }, baseMs: number = MFA_BACKOFF_DEFAULTS.baseMs, nowMs: number = Date.now()): { waitMs: number; spent: boolean } {
  if (row.failCount >= MFA_FAILURE_CAP) return { waitMs: 0, spent: true }
  if (!row.lastFailureAt) return { waitMs: 0, spent: false }
  const owed = new Date(row.lastFailureAt).getTime() + mfaBackoffMs(row.failCount, baseMs) - nowMs
  return { waitMs: Math.max(0, owed), spent: false }
}

/** The account's verified-factor counts (the sign-in's branch + the
 *  first-factor rule read it): passkeys, VERIFIED TOTP apps, and the
 *  recovery remainder. */
export async function factorCounts(store: ServerStore, userId: string): Promise<{ passkeys: number; totp: number; recoveryRemaining: number }> {
  const [passkeys, totp, recovery] = await Promise.all([
    store.listWebauthnCredentials(userId),
    store.listTotpSecrets(userId),
    store.recoveryCodeState(userId),
  ])
  return {
    passkeys: passkeys.length,
    totp: totp.filter(t => t.verifiedAt !== null).length,
    recoveryRemaining: recovery.remaining,
  }
}

/** The first-factor rule: called AFTER a factor lands (the TOTP verified,
 *  the passkey registered). When the account holds EXACTLY the one new
 *  factor and no recovery set exists yet, the recovery floor arrives with
 *  it — mint the set, answer the plaintext ONCE. Answers null when the
 *  moment is not the first (a later factor, or a set already present). */
export async function recoveryCodesAtFirstFactor(
  store: ServerStore,
  userId: string,
): Promise<string[] | null> {
  const counts = await factorCounts(store, userId)
  const recovery = await store.recoveryCodeState(userId)
  if (counts.passkeys + counts.totp !== 1 || recovery.total > 0) return null
  const codes = generateRecoveryCodes()
  const hashes = await Promise.all(codes.map(hashRecoveryCode))
  await store.replaceRecoveryCodes(userId, crypto.randomUUID(), hashes)
  return codes
}

/** The passkey sign-in's amr list: 'webauthn' always; 'hwk' when the
 *  registration's declared transports name a roaming authenticator
 *  (usb/nfc/ble — the hardware-key class). Attestation is 'none', so
 *  this records the browser's declaration, honestly — never a proof. */
export function passkeyAmr(transports: string[]): string[] {
  const amr = ['webauthn']
  if (transports.some(t => t === 'usb' || t === 'nfc' || t === 'ble')) amr.push('hwk')
  return amr
}

/** The factor wave's audit trail (the op-accounts discipline: the audit
 *  never blocks the path; entity_type 'account' so the console's own
 *  activity feed shows them and the admin dashboard's security signals
 *  read the same chain). */
export async function auditFactor(
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
    console.error(`[op] factor audit event ${action} failed to persist:`, (err as Error).message)
  }
}
