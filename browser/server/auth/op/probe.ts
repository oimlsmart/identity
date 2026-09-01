// ═══════════════════════════════════════════════════════════════════
// The status-probe recognition (the 2026-09-01 owner directive) — the
// estate's status service (oimlsmart/status, the id-auth-route leg)
// EXERCISES this OP's password sign-in every 60s with a known-
// nonexistent account: the fast 401 is the healthy answer, and the
// exercised path deliberately INCLUDES the audit write (the probe
// proves route → store read → timing-uniform verify → audit WRITE).
// Unlabeled, that honest cadence lands ~1440 account.sign_in_failed
// rows a day — visible noise in the activity feeds and, worse, poison
// in the failed-login BURST signal (TODO.identity-sso/01's security
// alarm for real credential attacks).
//
// The recognition: the probe presents the shared STATUS_PROBE_TOKEN (a
// Worker secret on BOTH workers, set with `wrangler secret put`, never
// committed) as the X-OIML-Probe header; the login route compares it
// constant-time (auth/op/secrets.ts's one implementation). The
// doctrine:
//
//   - an ABSENT or MISMATCHED header is a NORMAL caller — never an
//     error-path, timing, or response difference (the recognition only
//     ever re-labels the audit row, after the outcome is decided);
//   - the secret UNSET here turns the recognition off entirely (every
//     caller is normal);
//   - recognized AND the invalid-credentials failure → the row's action
//     is account.sign_in_probe: the same chain, the same row shape, the
//     honest label. The feeds (the account's own + the admin activity
//     surfaces) and the burst signal exclude it by default; the raw
//     chain retains it (the dashboard's queryable audit log carries it).
//
// WORKER-SAFE: WebCrypto-era primitives only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { timingSafeEqual } from './secrets'

/** The header the status probe presents (the shared token's vehicle). */
export const STATUS_PROBE_HEADER = 'x-oiml-probe'

/** Is this request the estate's status probe? True only when the
 *  STATUS_PROBE_TOKEN secret is configured AND the presented header
 *  matches it under the constant-time compare. Every other posture —
 *  the header absent, mismatched, or the secret unset — is a normal
 *  caller (the caller can never tell the difference). */
export function isStatusProbe(request: Request, env: Record<string, string | undefined>): boolean {
  const expected = env.STATUS_PROBE_TOKEN
  if (!expected) return false
  const presented = request.headers.get(STATUS_PROBE_HEADER)
  if (!presented) return false
  return timingSafeEqual(presented, expected)
}
