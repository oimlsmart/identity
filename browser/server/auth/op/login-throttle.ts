// ═══════════════════════════════════════════════════════════════════
// The password leg's per-account backoff ladder (TODO.identity-sso/04,
// slice C) — the twin of the second factor's hard throttle
// (auth/op/factors.ts's ladder, whose math this rides verbatim):
// every invalid-credentials failure on an address owes the NEXT attempt
// on that address a bounded wait (2^N × base, capped at 30 s), paid
// BEFORE the credential verify runs.
//
// The SILENT posture, deliberately unlike the second factor's:
//
//   - the answer NEVER changes shape: a throttled attempt still gets
//     the uniform 401 'Invalid email or password' (never a 429, never a
//     Retry-After, never a lockout flag) — the password leg's failure
//     classes stay indistinguishable, throttle state included;
//   - the wait is a DELAY, not a refusal: the right password still
//     verifies, just later — a holder mid-typo-storm is slowed, never
//     locked out, and a success clears the ladder outright;
//   - every failure still lands account.sign_in_failed on the audit
//     chain unchanged (the admin dashboard's burst signal reads it —
//     the throttle slows the spray; the chain still SEES it);
//   - the ladder keys on the normalized ADDRESS, account or not: an
//     unknown address accumulates the same waits (no enumeration
//     channel through the timing — the dummy-hash verify's doctrine
//     extended one rung earlier).
//
// The state rides the entity seam (the opLoginThrottle row, id = the
// normalized address): durable across isolate restarts, wiped by the
// dev-reset with everything else. The read-modify-write is not atomic
// (the entity seam carries no compare-and-swap): two concurrent
// failures can lose one rung — a soft throttle's acceptable slop,
// documented here. Within one request the row is read ONCE (alongside
// the credential read, one round-trip phase) and the rung write rides
// the audit write's phase — the same slop class, never re-read.
//
// The estate's 60 s status probe (auth/op/probe.ts) rides the ladder
// like every caller: its fixed address long ago passed the spent cap
// (failCount ≥ MFA_FAILURE_CAP ⇒ no wait owed), so the probe's timing
// stays the route's own — and the recognition keeps its own doctrine
// (it never shapes the answer, the timing, or an error path).
//
// The base is the deployment's (OP_LOGIN_BACKOFF_BASE_MS — the
// OP_MFA_BACKOFF_BASE_MS precedent; the tests declare small values so
// the ladder is exercised, not slept through).
//
// WORKER-SAFE: the store seam + setTimeout only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '@oimlsmart/platform-server/store'
import { MFA_BACKOFF_DEFAULTS, throttleState } from './factors'

/** The ladder's tuning: the base doubles per failure (the 30 s cap lives
 *  in the shared math — mfaBackoffMs's MFA_BACKOFF_DEFAULTS.capMs). */
export const LOGIN_BACKOFF_DEFAULTS = { baseMs: 1000 }

/** Resolve the backoff tuning from the env surface (invalid values fall
 *  back honestly, the problem named — the resolveMfaBackoffBaseMs
 *  posture). */
export function resolveLoginBackoffBaseMs(env: Record<string, string | undefined>): { baseMs: number; problems: string[] } {
  const problems: string[] = []
  let baseMs = LOGIN_BACKOFF_DEFAULTS.baseMs
  const raw = env.OP_LOGIN_BACKOFF_BASE_MS?.trim()
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw)
    if (!Number.isInteger(parsed) || parsed <= 0) {
      problems.push(`OP_LOGIN_BACKOFF_BASE_MS is not a positive integer: ${JSON.stringify(raw)} — the default ${LOGIN_BACKOFF_DEFAULTS.baseMs} applies`)
    } else {
      baseMs = parsed
    }
  }
  return { baseMs, problems }
}

// ── the ladder state (the entity seam's per-address row) ─────────────

const THROTTLE_STORE = 'opLoginThrottle'

/** The row IS the shared ladder's input shape (throttleState's row). */
export interface LoginThrottleRow {
  failCount: number
  lastFailureAt: string | null
}

/** The address's ladder row, read once per request (the route pairs it
 *  with the credential read — one round-trip phase). Never throws. */
export async function readLoginThrottleRow(store: ServerStore, email: string): Promise<LoginThrottleRow | undefined> {
  try {
    const row = await store.getEntity(THROTTLE_STORE, email)
    if (!row) return undefined
    const parsed = JSON.parse(row.data) as Partial<LoginThrottleRow>
    if (typeof parsed.failCount !== 'number') return undefined
    return { failCount: parsed.failCount, lastFailureAt: typeof parsed.lastFailureAt === 'string' ? parsed.lastFailureAt : null }
  } catch (err) {
    // A hiccup never breaks the sign-in path (the route's own store
    // reads would fail first; a corrupt row reads as no ladder).
    console.error('[op] the login throttle read failed:', (err as Error).message)
    return undefined
  }
}

/** The wait a read row owes the attempt NOW (0 = judge at once). Pure. */
export function loginThrottleWaitMsForRow(row: LoginThrottleRow | undefined, baseMs: number = LOGIN_BACKOFF_DEFAULTS.baseMs): number {
  if (!row) return 0
  return throttleState(row, baseMs).waitMs
}

/** The failure's rung: the count climbs off the request's own read (the
 *  row is not re-read — see the header's one-read doctrine), the
 *  timestamp restarts the wait. Never throws (the audit chain's
 *  sign_in_failed row is the durable record either way). */
export async function recordLoginThrottleFailure(store: ServerStore, email: string, prior: LoginThrottleRow | undefined): Promise<void> {
  try {
    const row: LoginThrottleRow = { failCount: (prior?.failCount ?? 0) + 1, lastFailureAt: new Date().toISOString() }
    await store.putEntity(THROTTLE_STORE, email, null, JSON.stringify(row))
  } catch (err) {
    console.error('[op] the login throttle write failed:', (err as Error).message)
  }
}

/** A successful password verify clears the ladder outright. */
export async function clearLoginThrottle(store: ServerStore, email: string): Promise<void> {
  try {
    if (await readLoginThrottleRow(store, email)) await store.deleteEntity(THROTTLE_STORE, email)
  } catch (err) {
    console.error('[op] the login throttle clear failed:', (err as Error).message)
  }
}

/** The delay helper, exported for the route (the bounded wait, paid
 *  before the verify — a sleeping isolate serves other requests; the
 *  ceiling is the shared ladder cap, never unbounded). */
export function delayMs(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, Math.min(Math.max(0, ms), MFA_BACKOFF_DEFAULTS.capMs)))
}
