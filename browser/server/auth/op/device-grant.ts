// ═══════════════════════════════════════════════════════════════════
// The RFC 8628 device authorization grant (TODO.ai-platform/10) — the
// user-attended flow that lets a CLI act AS the account holder with no
// secret paste (the `gh auth login` pattern):
//
//   1. the CLI POSTs /op/device/authorization (client_id + the scope ask
//      in the PAT grammar) and receives the device_code (its poll
//      credential), the user_code (what the holder types), and the
//      verification URIs;
//   2. the holder signs in at /op/device, reads the ask (the services +
//      the action classes, named honestly), approves or denies — the
//      decision re-judges the scope set against the APPROVING account's
//      live standing (resolvePatScopesForAccount, the console mint's
//      own computation), never against a guess;
//   3. the CLI polls /op/token (grant_type device_code) and, on
//      approval, receives the personal access token's PLAINTEXT — the
//      row mints at that moment through the one store path, so the
//      plaintext shows exactly once, in the answer that delivers it
//      (the GitHub doctrine); the audit names the device grant and the
//      client; the mint's security mail rides.
//
// The ceremonies die fast (the codes expire in minutes — the approval
// is a live act), the poll judgment speaks §3.5 verbatim
// (authorization_pending / slow_down / access_denied / expired_token),
// and the device_code consumes ONE time (a re-present answers
// invalid_grant).
//
// THE SCOPE MODEL: the ask is the PAT grammar's `<service>:<action-
// class>` set — the device flow is a bootstrap for the PAT cone, not an
// OIDC ceremony (no ID token, no userinfo). The delivered credential IS
// a personal access token: the CLI exchanges it at the RFC 8693 grant
// for the short-lived OP JWT per use, exactly like a console-minted
// PAT. The catalog-permission cone (TODO.openapi/03) stays a CONSOLE
// act — a device-granted token carries no catalog permissions at mint
// (the holder adds them deliberately in the console, fresh-auth gated).
//
// WORKER-SAFE: WebCrypto only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { getStore, type DeviceAuthorization } from '../../store'
import { opRandomToken } from './keys'
import { hashPat } from './tokens'

// ── the wire constants ───────────────────────────────────────────────

/** The RFC 8628 grant the CLI speaks at /op/token. */
export const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'

/** The ceremony's bounds: the codes live ≤ 10 minutes (the approval is
 *  a live act); the poll interval starts at 5 seconds. */
export const DEVICE_AUTHORIZATION_TTL_MS = 10 * 60_000
export const DEVICE_POLL_INTERVAL_SECONDS = 5
/** §3.5's slow_down growth: a poll inside the interval adds 5. */
export const DEVICE_SLOWDOWN_INCREMENT_SECONDS = 5

/** The minted PAT's name (the console list labels by it — the holder
 *  reads WHICH client and WHICH ceremony). */
export function deviceGrantPatName(clientName: string, now = new Date()): string {
  return `${clientName} — device grant — ${now.toISOString().slice(0, 10)}`
}

// ── the codes ────────────────────────────────────────────────────────

/** The device_code: the CLI's poll credential — 32 random bytes,
 *  base64url (the one-time access-token shape). */
export function mintDeviceCode(): string {
  return opRandomToken()
}

/** The Crockford base32 alphabet (no I, L, O, U — the human-typed code
 *  never carries the confusables). */
const USER_CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** The user_code: 8 Crockford chars in the XXXX-XXXX shape (the holder
 *  types it — the alphabet and the grouping are the human factors). */
export function mintUserCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8))
  const chars = [...bytes].map(b => USER_CODE_ALPHABET[b % 32])
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`
}

/** The holder-entered code's canonical form: uppercase, dashes and
 *  spaces stripped, the Crockford decode aliases folded (O→0, I/L→1).
 *  Answers null when what remains is not the 8-char alphabet shape —
 *  the lookup simply never runs on a malformed entry. */
export function normalizeUserCode(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const folded = raw.toUpperCase().replace(/[\s-]+/g, '')
    .replace(/O/g, '0').replace(/[IL]/g, '1')
  if (!/^[0-9A-HJKMNP-TV-Z]{8}$/.test(folded)) return null
  return `${folded.slice(0, 4)}-${folded.slice(4)}`
}

/** The store's lookup keys (the PAT doctrine: SHA-256 of the presented
 *  value — the rows never hold a plaintext code). hashPat's own
 *  computation, shared verbatim. */
export const hashDeviceCode: (code: string) => Promise<string> = hashPat
export const hashUserCode: (code: string) => Promise<string> = hashPat

// ── the poll judgment (RFC 8628 §3.5) ────────────────────────────────

export type DevicePollVerdict =
  | { kind: 'pending' }
  | { kind: 'slow_down'; intervalSeconds: number }
  | { kind: 'denied' }
  | { kind: 'expired' }
  | { kind: 'consumed' }
  | { kind: 'approved' }

/** The one computation the token leg's answers ride (the row already
 *  read): expired wins over every state (a decided row past its TTL
 *  answers expired_token, never the decision — the ceremony is dead);
 *  consumed is its own verdict (a re-presented used code — the leg
 *  answers invalid_grant, never a fresh pending); a pending row polled
 *  INSIDE the interval is the slow_down (the interval grows by §3.5's
 *  increment). The approved kind is the leg's cue to claim the row
 *  ATOMICALLY (consumeDeviceAuthorization) — a race that loses reads
 *  consumed on the retry, never a second token. */
export function judgeDevicePoll(row: DeviceAuthorization, now = Date.now()): DevicePollVerdict {
  if (new Date(row.expiresAt).getTime() <= now) return { kind: 'expired' }
  if (row.status === 'consumed') return { kind: 'consumed' }
  if (row.status === 'denied') return { kind: 'denied' }
  if (row.status === 'approved') return { kind: 'approved' }
  if (row.lastPollAt && now - new Date(row.lastPollAt).getTime() < row.intervalSeconds * 1000) {
    return { kind: 'slow_down', intervalSeconds: row.intervalSeconds + DEVICE_SLOWDOWN_INCREMENT_SECONDS }
  }
  return { kind: 'pending' }
}

// ── the audit chain ──────────────────────────────────────────────────

/** The ceremony acts land on the ACCOUNT's feed once an account exists
 *  (the decision onward); the account-free request leg audits on the
 *  CLIENT (the op.ts audit seam's posture). This helper mirrors
 *  tokens.ts's auditPat exactly (entity_type 'account', best-effort). */
export async function auditDeviceGrant(
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
    console.error(`[op] device-grant audit event ${action} failed to persist:`, (err as Error).message)
  }
}
