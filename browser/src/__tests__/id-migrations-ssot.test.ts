// ─────────────────────────────────────────────────────────────────────
// The migrations' byte-identity tripwire (the AGENTS.md rule:
// browser/server/db/migrations/ is byte-identical with the monorepo's
// set — wrangler keys the D1 bookkeeping on FILENAMES, so the two copies
// drifting would split the live registry's history). The monorepo's own
// suite pins the migrations' end state to the kernel's schema.sql; this
// leg pins the two REPOS' sets to each other.
//
// The kernel checkout rides the x/ doctrine (x/oimlsmart/smart, the
// declared file: position — CI checks it out at the same path). Absent
// the checkout the leg SKIPS honestly (a docs-only local run never
// blocks on it).
// ─────────────────────────────────────────────────────────────────────

import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const BROWSER = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const LOCAL = join(BROWSER, 'server', 'db', 'migrations')
const KERNEL = join(BROWSER, '..', 'x', 'oimlsmart', 'smart', 'browser', 'server', 'db', 'migrations')

// The LOCAL-ONLY allowance (the house allowlist doctrine: dated,
// wave-referenced, and only ever SHRINKS): files this repo carries
// ahead of their monorepo mirror. 0017's mirror is the coordinator's
// follow-up in the kernel-extraction wave (the migration's own header
// states it); when the mirror lands on the monorepo's branch the entry
// leaves this list and the sets compare equal again.
const LOCAL_ONLY_PENDING_MIRROR: readonly string[] = [
  '0017_org_member_cones.sql', // TODO.identity-features/09, 2026-08-27
]

describe('the D1 migrations’ byte-identity (identity ≡ monorepo)', () => {
  it('the two sets are the same files with the same bytes', () => {
    if (!existsSync(KERNEL)) {
      console.warn('[id] the kernel checkout (x/oimlsmart/smart) is absent — the byte-identity leg skips (CI declares it)')
      return
    }
    const localFiles = readdirSync(LOCAL).filter(f => f.endsWith('.sql')).sort()
    const kernelFiles = readdirSync(KERNEL).filter(f => f.endsWith('.sql')).sort()
    const localOnly = localFiles.filter(f => !kernelFiles.includes(f))
    expect(
      localOnly,
      `files beyond the dated mirror allowance drifted (a wave landed on one side only?): ${localOnly.join(', ')}`,
    ).toEqual([...LOCAL_ONLY_PENDING_MIRROR])
    const shared = localFiles.filter(f => kernelFiles.includes(f))
    expect(
      kernelFiles.filter(f => !localFiles.includes(f)),
      'the monorepo carries a migration this repo lacks — the identity repo owns the live registry, pull the mirror here',
    ).toEqual([])
    for (const f of shared) {
      const local = readFileSync(join(LOCAL, f), 'utf-8')
      const kernel = readFileSync(join(KERNEL, f), 'utf-8')
      expect(local === kernel, `${f} drifted between the repos`).toBe(true)
    }
  })
})
