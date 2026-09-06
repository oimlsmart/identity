// ═══════════════════════════════════════════════════════════════════
// The breached-password check (TODO.identity-sso/04, slice B) — the
// k-anonymity query against a Pwned-Passwords-shaped range API at the
// two moments a password is CHOSEN (the enrollment's set + the account
// console's change):
//
//   - the password never leaves the deployment: SHA-1 locally, the
//     FIRST FIVE hex characters go out, the answer is the range of
//     every hash sharing them; the match happens here;
//   - a BREACHED password is REFUSED (the plain-language 400) — the
//     refusal lands before any token or credential row is touched, so
//     the setup link stays unspent and the current password stays in
//     force;
//   - an UNREACHABLE corpus never strands the holder: the password is
//     ACCEPTED, the mutation's audit event carries
//     breachCheck:'unreachable', and the per-account marker (the
//     opPasswordBreach entity row) arms the RE-CHECK at the next
//     successful password sign-in — the presented password re-runs the
//     query, the outcome lands on the audit chain
//     (account.password_breach_recheck, the holder's own feed
//     included), and a definitive verdict disarms the marker. A
//     breached verdict at the re-check never strands the sign-in
//     either: the holder is already in; the feed + the chain carry it.
//
// The range endpoint is the deployment's (HIBP_RANGE_URL — the honest
// seam for a proxy, a self-hosted corpus, and the tests' stub; the
// literal 'off' DISABLES the check outright — the declared posture of
// an offline estate and of every test suite that is not the check's
// own pin: no query, no marker, no audit note). The query is bounded
// (HIBP_TIMEOUT_MS) and NEVER throws: every failure mode resolves to
// 'unknown'.
//
// WORKER-SAFE: WebCrypto + fetch + the store seam only, no node
// built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '@oimlsmart/platform-server/store'

export type HibpVerdict = 'clean' | 'breached' | 'unknown' | 'disabled'

/** The corpus query's ceiling: a hung range API never holds the
 *  password ceremony (the failure resolves to 'unknown'). */
export const HIBP_TIMEOUT_MS = 4_000

/** The two password-choosing routes' shared refusal (op-accounts.ts's
 *  enrollment completion + password change answer the same words). */
export const HIBP_BREACHED_REFUSAL = 'That password appears in a known data breach — it is one of the first things an attacker tries. Choose a different one (a password manager’s generated password is the strong default).'

const HIBP_DEFAULT_RANGE_URL = 'https://api.pwnedpasswords.com/range'

/** The deployment's range endpoint (the resolve* posture: an invalid
 *  declaration falls back honestly, the problem named). null = the
 *  declared 'off' — the check is disabled, honestly and silently. */
export function resolveHibpRangeUrl(env: Record<string, string | undefined>): { rangeUrl: string | null; problems: string[] } {
  const raw = env.HIBP_RANGE_URL?.trim()
  if (raw === undefined || raw === '') return { rangeUrl: HIBP_DEFAULT_RANGE_URL, problems: [] }
  if (raw.toLowerCase() === 'off') return { rangeUrl: null, problems: [] }
  if (!/^https?:\/\//.test(raw)) {
    return { rangeUrl: HIBP_DEFAULT_RANGE_URL, problems: [`HIBP_RANGE_URL must be an absolute http(s) URL (or 'off'): ${JSON.stringify(raw)} — the default ${HIBP_DEFAULT_RANGE_URL} applies`] }
  }
  return { rangeUrl: raw.replace(/\/+$/, ''), problems: [] }
}

/** The k-anonymity verdict for a candidate password. NEVER throws:
 *  every transport/parse failure is 'unknown' (the accept-and-recheck
 *  half of the doctrine); the declared 'off' is 'disabled' (no marker,
 *  no audit note — the deployment's own posture, not an outage). */
export async function hibpPasswordVerdict(password: string, env: Record<string, string | undefined>): Promise<HibpVerdict> {
  const { rangeUrl, problems } = resolveHibpRangeUrl(env)
  for (const problem of problems) console.warn(`[hibp] ${problem}`)
  if (rangeUrl === null) return 'disabled'
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password)))
    const hex = [...digest].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
    const res = await fetch(`${rangeUrl}/${hex.slice(0, 5)}`, {
      headers: {
        'user-agent': 'oiml-smart-identity breached-password check',
        // The corpus's own traffic-analysis mitigation (padded answers —
        // ignored by any endpoint that does not honor it).
        'add-padding': 'true',
      },
      signal: AbortSignal.timeout(HIBP_TIMEOUT_MS),
    })
    if (!res.ok) return 'unknown'
    const suffix = hex.slice(5)
    const body = await res.text()
    for (const line of body.split('\n')) {
      // A row is SUFFIX:count (the suffix may carry the CR of a CRLF).
      if (line.split(':', 1)[0]!.trim().toUpperCase() === suffix) return 'breached'
    }
    return 'clean'
  } catch {
    return 'unknown'
  }
}

// ── the deferred re-check's marker (the entity seam's per-account row) ──

const RECHECK_STORE = 'opPasswordBreach'

interface BreachRecheckMarker {
  pending: boolean
  markedAt: string
}

/** The account's armed re-check marker. A read/parse failure answers
 *  false (a marker hiccup never blocks the sign-in path — the audit
 *  chain's breachCheck:'unreachable' note is the record). */
export async function breachRecheckPending(store: ServerStore, userId: string): Promise<boolean> {
  try {
    const row = await store.getEntity(RECHECK_STORE, userId)
    if (!row) return false
    return (JSON.parse(row.data) as Partial<BreachRecheckMarker>).pending === true
  } catch (err) {
    console.error('[op] the breach re-check marker read failed:', (err as Error).message)
    return false
  }
}

/** Arm the re-check (the corpus was unreachable when the password was
 *  chosen). Idempotent: the newest markedAt stands. Never throws — the
 *  marker ride-along never fails the password mutation that earned it. */
export async function markBreachRecheck(store: ServerStore, userId: string): Promise<void> {
  try {
    const marker: BreachRecheckMarker = { pending: true, markedAt: new Date().toISOString() }
    await store.putEntity(RECHECK_STORE, userId, null, JSON.stringify(marker))
  } catch (err) {
    console.error('[op] the breach re-check marker write failed:', (err as Error).message)
  }
}

/** The re-check's verdict: a definitive answer disarms the marker (the
 *  audit event carries the outcome); a STILL-unreachable corpus keeps
 *  the marker armed for the next sign-in. */
export async function resolveBreachRecheck(store: ServerStore, userId: string, outcome: HibpVerdict): Promise<void> {
  if (outcome === 'unknown') return
  try {
    await store.deleteEntity(RECHECK_STORE, userId)
  } catch (err) {
    console.error('[op] the breach re-check marker clear failed:', (err as Error).message)
  }
}
