// ─────────────────────────────────────────────────────────────────────
// The bootstrap seeds' read-back arbiter (the 2026-09-23 lesson).
//
// The per-isolate bootstrap seeds (accounts, the client registry, the
// upstream registry) ride the store's bounded-write discipline: a write
// whose CONFIRMATION does not arrive within the budget throws
// StoreUnavailable — and that error never claims the write was lost
// (the store may have accepted the statement; the confirm path hung).
// The seed wrappers' retry posture then re-ran the whole seed on the
// next credential request — and while a seed kept failing, the login
// it guarded answered 503, EVEN WHEN the seed's content had already
// landed.
//
// The honest arbiter is a READ-BACK: the seed side is idempotent, so
// "every declared row reads back" IS the seed's success condition. On
// a timed-out confirm the guard reads the declared content back and
// PROCEEDS when it is complete (the login must not die for a seed that
// already landed); a genuinely incomplete seed keeps the exact retry
// posture (the error rethrows, the wrapper clears its memo, the next
// credential request retries). The enrollment links the account seed
// mints re-mint on the next seed run by design (a fresh link at every
// boot until the password is set), so a skipped mint is the posture,
// not a gap.
//
// The read-back itself rides the store's READS — never budgeted — so
// the arbiter cannot fail by the same timeout that triggered it.
// ─────────────────────────────────────────────────────────────────────

import { StoreUnavailable } from '../store'

/** Run one seed step; a timed-out write-confirm does not fail it when
 *  the read-back proves the content landed. Answers the seed's own
 *  return (the ids it created); the verified-timeout path answers []
 *  (nothing was proven NEWLY created by this run). */
export async function seedWithReadBack<T>(
  label: string,
  seed: () => Promise<T[]>,
  verify: () => Promise<boolean>,
): Promise<T[]> {
  try {
    return await seed()
  } catch (err) {
    // Only a TIMED-OUT WRITE confirm earns the arbiter; every other
    // failure keeps the retry posture untouched.
    if (!(err instanceof StoreUnavailable)) throw err
    if (!(await verify())) throw err
    console.warn(`[op] the ${label} seed's write confirm timed out — the read-back proves the content landed; proceeding`)
    return []
  }
}
