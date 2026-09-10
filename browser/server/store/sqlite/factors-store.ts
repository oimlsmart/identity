// ═══════════════════════════════════════════════════════════════════
// The factor registry's SQLite half (TODO.identity-sso/02 passkeys + /03
// the factor registry) — the sync implementations behind the ServerStore
// strong-authentication methods (sqlite-server-store.ts delegates here
// one-for-one, mirroring op-accounts-store.ts's role for the account
// model). The D1 store implements the same surface in d1.ts.
//
// The doctrines carried:
//   - ONE-TIME means one-time: challenges, the pending-MFA row and the
//     recovery codes consume via guarded UPDATEs (consumed_at IS NULL) —
//     a replay/concurrent double loses the race, honestly;
//   - the signature counter's advance is a GUARDED update (the clone
//     rule): a regressed counter never lands, and the refusal is named
//     ('regressed') for the audit event;
//   - the throttles ride the ROWS (fail_count + last_failure_at on the
//     pending enrollment / the pending sign-in) — the database is the
//     proof, never a per-process Map;
//   - recovery codes are stored HASHED (SHA-256 of the normalized code);
//     the plaintext is shown once at generation and never persists.
//
// NODE-ONLY: better-sqlite3 through ./store's getDb. The Worker bundle
// never sees this module.
// ═══════════════════════════════════════════════════════════════════

import { randomUUID } from 'crypto'
import { getDb } from './store'
import type {
  AdvanceCounterResult,
  MfaPending,
  RecoveryCodeState,
  TotpSecret,
  WebauthnChallenge,
  WebauthnCredential,
} from '../../store'

// ── row mappers ──────────────────────────────────────────────────────

/** The store's time columns arrive in two shapes: datetime('now')'s
 *  UTC-but-unadorned 'YYYY-MM-DD HH:MM:SS' (the DEFAULT writes) and the
 *  ISO strings the code paths write explicitly. The API answers ISO
 *  always (Date.parse treats the naive shape as LOCAL time — the age
 *  math the routes run would misfire off-UTC). */
export function storeTimeToIso(value: string | null): string | null {
  if (value === null) return null
  if (value.includes('T')) return value
  return value.replace(' ', 'T') + 'Z'
}

function toWebauthnCredential(row: Record<string, unknown>): WebauthnCredential {
  let transports: string[] = []
  try {
    const parsed = JSON.parse((row.transports as string | null) ?? '[]') as unknown
    if (Array.isArray(parsed)) transports = parsed.filter((t): t is string => typeof t === 'string')
  } catch { /* a malformed JSON array never breaks the read — the empty list is honest */ }
  return {
    credentialId: row.credential_id as string,
    userId: row.user_id as string,
    name: row.name as string,
    publicKeyCose: row.public_key as string,
    signCount: Number(row.sign_count ?? 0),
    aaguid: (row.aaguid as string | null) ?? null,
    transports,
    createdAt: storeTimeToIso(row.created_at as string)!,
    lastUsedAt: storeTimeToIso((row.last_used_at as string | null) ?? null),
    lastIp: (row.last_ip as string | null) ?? null,
  }
}

function toTotpSecret(row: Record<string, unknown>): TotpSecret {
  return {
    id: row.id as string,
    userId: row.user_id as string,
    name: row.name as string,
    secret: row.secret as string,
    failCount: Number(row.fail_count ?? 0),
    lastFailureAt: storeTimeToIso((row.last_failure_at as string | null) ?? null),
    createdAt: storeTimeToIso(row.created_at as string)!,
    verifiedAt: storeTimeToIso((row.verified_at as string | null) ?? null),
    lastUsedAt: storeTimeToIso((row.last_used_at as string | null) ?? null),
    lastIp: (row.last_ip as string | null) ?? null,
  }
}

function toWebauthnChallenge(row: Record<string, unknown>): WebauthnChallenge {
  return {
    challenge: row.challenge as string,
    userId: (row.user_id as string | null) ?? null,
    kind: row.kind as WebauthnChallenge['kind'],
    createdAt: storeTimeToIso(row.created_at as string)!,
    expiresAt: storeTimeToIso(row.expires_at as string)!,
    consumedAt: storeTimeToIso((row.consumed_at as string | null) ?? null),
  }
}

function toMfaPending(row: Record<string, unknown>): MfaPending {
  let amr: string[] = []
  try {
    const parsed = JSON.parse(row.amr as string) as unknown
    if (Array.isArray(parsed)) amr = parsed.filter((a): a is string => typeof a === 'string')
  } catch { /* a malformed amr list reads as none — the row is mid-flight state */ }
  return {
    token: row.token as string,
    userId: row.user_id as string,
    amr,
    failCount: Number(row.fail_count ?? 0),
    lastFailureAt: storeTimeToIso((row.last_failure_at as string | null) ?? null),
    createdAt: storeTimeToIso(row.created_at as string)!,
    expiresAt: storeTimeToIso(row.expires_at as string)!,
    consumedAt: storeTimeToIso((row.consumed_at as string | null) ?? null),
  }
}

// ── the WebAuthn ceremony challenges (one-time, short-TTL) ───────────

export function createWebauthnChallenge(input: {
  challenge: string
  userId: string | null
  kind: WebauthnChallenge['kind']
  ttlMs: number
}): void {
  const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
  const db = getDb()
  // The sweep rides the write (the putSsoState pattern): expired rows go.
  db.prepare("DELETE FROM webauthn_challenges WHERE expires_at <= datetime('now')").run()
  db.prepare(
    'INSERT INTO webauthn_challenges (challenge, user_id, kind, expires_at) VALUES (?, ?, ?, ?)',
  ).run(input.challenge, input.userId, input.kind, expiresAt)
}

/** Consume atomically: the row answers exactly once; an expired row is
 *  consumed too (burned on presentation, never redeemed later). */
export function consumeWebauthnChallenge(challenge: string): WebauthnChallenge | null {
  const db = getDb()
  const res = db.prepare(
    "UPDATE webauthn_challenges SET consumed_at = datetime('now') WHERE challenge = ? AND consumed_at IS NULL",
  ).run(challenge)
  if (res.changes === 0) return null
  const row = db.prepare('SELECT * FROM webauthn_challenges WHERE challenge = ?').get(challenge) as Record<string, unknown> | undefined
  if (!row) return null
  if (new Date(row.expires_at as string).getTime() <= Date.now()) return null
  return toWebauthnChallenge(row)
}

// ── the passkeys ─────────────────────────────────────────────────────

/** Register the passkey; answers null on the credential-id conflict (the
 *  PRIMARY KEY is the race backstop — one authenticator registers once,
 *  to one account). */
export function createWebauthnCredential(input: {
  credentialId: string
  userId: string
  name: string
  publicKeyCose: string
  signCount: number
  aaguid: string | null
  transports: string[]
  ip?: string | null
}): WebauthnCredential | null {
  const db = getDb()
  try {
    db.prepare(
      `INSERT INTO webauthn_credentials
         (credential_id, user_id, name, public_key, sign_count, aaguid, transports, last_ip)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      input.credentialId, input.userId, input.name, input.publicKeyCose,
      Math.max(0, Math.floor(input.signCount)), input.aaguid, JSON.stringify(input.transports),
      input.ip ?? null,
    )
  } catch (e) {
    if (String((e as Error).message).includes('UNIQUE')) return null
    throw e
  }
  return getWebauthnCredential(input.credentialId)
}

export function listWebauthnCredentials(userId: string): WebauthnCredential[] {
  const rows = getDb().prepare(
    'SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at, credential_id',
  ).all(userId) as Array<Record<string, unknown>>
  return rows.map(toWebauthnCredential)
}

export function getWebauthnCredential(credentialId: string): WebauthnCredential | null {
  const row = getDb().prepare(
    'SELECT * FROM webauthn_credentials WHERE credential_id = ?',
  ).get(credentialId) as Record<string, unknown> | undefined
  return row ? toWebauthnCredential(row) : null
}

export function deleteWebauthnCredential(userId: string, credentialId: string): boolean {
  return getDb().prepare(
    'DELETE FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?',
  ).run(credentialId, userId).changes > 0
}

/** The guarded counter advance (the clone rule, in SQL so the check and
 *  the write are one act): lands when the pair is (0 → 0) — the
 *  authenticator never counts — or strictly increasing; a zeroed or
 *  behind counter against a started one is the regression signal. */
export function advanceWebauthnCounter(
  credentialId: string,
  newCount: number,
  opts?: { ip?: string | null },
): AdvanceCounterResult {
  const db = getDb()
  const count = Math.max(0, Math.floor(newCount))
  const res = db.prepare(
    `UPDATE webauthn_credentials
     SET sign_count = ?, last_used_at = datetime('now'), last_ip = ?
     WHERE credential_id = ? AND ((sign_count = 0 AND ? = 0) OR sign_count < ?)`,
  ).run(count, opts?.ip ?? null, credentialId, count, count)
  if (res.changes > 0) return 'ok'
  return getWebauthnCredential(credentialId) ? 'regressed' : 'unknown'
}

// ── the TOTP authenticator apps ──────────────────────────────────────

/** The enrollment's PENDING row (verified_at NULL — the factor activates
 *  at markTotpSecretVerified, never before). */
export function createTotpSecret(input: { id: string; userId: string; name: string; secret: string }): TotpSecret {
  getDb().prepare(
    'INSERT INTO totp_secrets (id, user_id, name, secret) VALUES (?, ?, ?, ?)',
  ).run(input.id, input.userId, input.name, input.secret)
  return getTotpSecret(input.id)!
}

export function listTotpSecrets(userId: string): TotpSecret[] {
  const rows = getDb().prepare(
    'SELECT * FROM totp_secrets WHERE user_id = ? ORDER BY created_at, id',
  ).all(userId) as Array<Record<string, unknown>>
  return rows.map(toTotpSecret)
}

export function getTotpSecret(id: string): TotpSecret | null {
  const row = getDb().prepare('SELECT * FROM totp_secrets WHERE id = ?').get(id) as Record<string, unknown> | undefined
  return row ? toTotpSecret(row) : null
}

export function markTotpSecretVerified(id: string, userId: string, name: string): boolean {
  return getDb().prepare(
    "UPDATE totp_secrets SET verified_at = datetime('now'), name = ? WHERE id = ? AND user_id = ? AND verified_at IS NULL",
  ).run(name, id, userId).changes > 0
}

/** The enrollment verify's failure ladder (the six-digit window's wall):
 *  increments fail_count and stamps the failure instant; answers the
 *  fresh count (0 when the row is gone or not the account's). */
export function recordTotpEnrollFailure(id: string, userId: string): number {
  const db = getDb()
  const res = db.prepare(
    "UPDATE totp_secrets SET fail_count = fail_count + 1, last_failure_at = datetime('now') WHERE id = ? AND user_id = ? AND verified_at IS NULL",
  ).run(id, userId)
  if (res.changes === 0) return 0
  const row = db.prepare('SELECT fail_count AS n FROM totp_secrets WHERE id = ?').get(id) as { n: number } | undefined
  return row?.n ?? 0
}

export function markTotpSecretUsed(id: string, opts?: { ip?: string | null }): void {
  getDb().prepare(
    "UPDATE totp_secrets SET last_used_at = datetime('now'), last_ip = ? WHERE id = ?",
  ).run(opts?.ip ?? null, id)
}

export function deleteTotpSecret(userId: string, id: string): boolean {
  return getDb().prepare('DELETE FROM totp_secrets WHERE id = ? AND user_id = ?').run(id, userId).changes > 0
}

// ── the recovery codes ───────────────────────────────────────────────

/** Replace the account's set WHOLE (the regenerate): the old batch goes,
 *  the new hashes land — one transaction, so a crash never leaves the
 *  account with no codes while the console shows fresh ones. */
export function replaceRecoveryCodes(userId: string, batch: string, codeHashes: string[]): void {
  const db = getDb()
  db.transaction(() => {
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId)
    const insert = db.prepare(
      'INSERT INTO recovery_codes (id, user_id, batch, code_hash) VALUES (?, ?, ?, ?)',
    )
    for (const hash of codeHashes) insert.run(randomUUID(), userId, batch, hash)
  })()
}

export function recoveryCodeState(userId: string): RecoveryCodeState {
  const row = getDb().prepare(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN consumed_at IS NULL THEN 1 ELSE 0 END) AS remaining,
            MAX(created_at) AS created_at
     FROM recovery_codes WHERE user_id = ?`,
  ).get(userId) as { total: number; remaining: number | null; created_at: string | null }
  return {
    total: row.total,
    remaining: row.remaining ?? 0,
    createdAt: row.total > 0 ? row.created_at : null,
  }
}

/** The one-time use: consumed_at flips atomically on the matching
 *  unconsumed row — true exactly once per code. */
export function consumeRecoveryCode(userId: string, codeHash: string): boolean {
  return getDb().prepare(
    "UPDATE recovery_codes SET consumed_at = datetime('now') WHERE user_id = ? AND code_hash = ? AND consumed_at IS NULL",
  ).run(userId, codeHash).changes > 0
}

// ── the pending second-factor sign-in ────────────────────────────────

export function createMfaPending(input: { token: string; userId: string; amr: string[]; ttlMs: number }): void {
  const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
  const db = getDb()
  // The sweep rides the write (the challenge table's pattern).
  db.prepare("DELETE FROM mfa_pending WHERE expires_at <= datetime('now')").run()
  db.prepare(
    'INSERT INTO mfa_pending (token, user_id, amr, expires_at) VALUES (?, ?, ?, ?)',
  ).run(input.token, input.userId, JSON.stringify(input.amr), expiresAt)
}

export function getMfaPending(token: string): MfaPending | null {
  const row = getDb().prepare('SELECT * FROM mfa_pending WHERE token = ?').get(token) as Record<string, unknown> | undefined
  return row ? toMfaPending(row) : null
}

/** The completion: consumed ATOMICALLY (a concurrent completion loses);
 *  an expired row burns on presentation, never redeems later. */
export function consumeMfaPending(token: string): MfaPending | null {
  const db = getDb()
  const res = db.prepare(
    "UPDATE mfa_pending SET consumed_at = datetime('now') WHERE token = ? AND consumed_at IS NULL",
  ).run(token)
  if (res.changes === 0) return null
  const row = db.prepare('SELECT * FROM mfa_pending WHERE token = ?').get(token) as Record<string, unknown> | undefined
  if (!row) return null
  if (new Date(row.expires_at as string).getTime() <= Date.now()) return null
  return toMfaPending(row)
}

/** The failure ladder: fail_count++ + last_failure_at on the LIVE row
 *  (a consumed one takes no more failures); answers the fresh row. */
export function recordMfaPendingFailure(token: string): MfaPending | null {
  const db = getDb()
  const res = db.prepare(
    "UPDATE mfa_pending SET fail_count = fail_count + 1, last_failure_at = datetime('now') WHERE token = ? AND consumed_at IS NULL",
  ).run(token)
  if (res.changes === 0) return null
  const row = db.prepare('SELECT * FROM mfa_pending WHERE token = ?').get(token) as Record<string, unknown> | undefined
  return row ? toMfaPending(row) : null
}
