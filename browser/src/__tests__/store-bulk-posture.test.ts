// ─────────────────────────────────────────────────────────────────────
// The bulk sign-in-posture + identity-links reads (identity's
// TODO.restructure/06 — the endpoint-scaling budgets' kernel-side
// answer), proven against a REAL temp SQLite store:
//
//   PARITY   for every account, the bulk reads answer EXACTLY what the
//            per-id reads answer (the counts object; the links array,
//            ORDER included) — the identity routes may swap the per-row
//            loops for the bulk reads with byte-compatible answers;
//   HONESTY  every requested id answers (an unknown id: zero counts,
//            the empty array — the per-id read's own posture); an empty
//            request answers an empty map, never a throw.
//
// The D1 surface's identical SQL (plus the ONE-batch count trip) runs
// in the monorepo's d1-store suite against the D1-binding facade.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-bulk-posture-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

let store: ReturnType<typeof import('../../server/store/sqlite').createSqliteServerStore>

beforeAll(async () => {
  const { createSqliteServerStore } = await import('../../server/store/sqlite')
  store = createSqliteServerStore()
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
})

describe('the bulk sign-in-posture reads (sqlite)', () => {
  it('PARITY: the bulk reads answer the per-id reads, order included', async () => {
    const a = (await store.createOpAccount({ email: 'bulk-a@example.org', name: 'Bulk A', role: 'viewer', createdBy: 'test' }))!
    const b = (await store.createOpAccount({ email: 'bulk-b@example.org', name: 'Bulk B', role: 'viewer', createdBy: 'test' }))!
    const c = (await store.createOpAccount({ email: 'bulk-c@example.org', name: 'Bulk C', role: 'viewer', createdBy: 'test' }))!

    // A: password + two links + one passkey. B: one link only. C: nothing.
    await store.setPasswordHash(a.id, 'x' as string, 'test')
    await store.createIdentityLink({ userId: a.id, provider: 'github', providerAccountId: 'gh-a1', linkedBy: null })
    await store.createIdentityLink({ userId: a.id, provider: 'google', providerAccountId: 'go-a1', linkedBy: null })
    await store.createWebauthnCredential({
      credentialId: 'bulk-cred-1', userId: a.id, name: 'Bulk key', publicKeyCose: 'cose',
      signCount: 0, aaguid: null, transports: ['internal'],
    })
    await store.createIdentityLink({ userId: b.id, provider: 'github', providerAccountId: 'gh-b1', linkedBy: null })

    const ids = [a.id, b.id, c.id, 'no-such-account']
    const counts = await store.countSignInMethodsBulk(ids)
    const links = await store.listIdentityLinksBulk(ids)

    for (const id of ids) {
      expect(counts.get(id), `counts parity for ${id}`).toEqual(await store.countSignInMethods(id))
      expect(links.get(id), `links parity for ${id}`).toEqual(await store.listIdentityLinks(id))
    }

    // The mixed postures actually differ (the parity above is not vacuous).
    expect(counts.get(a.id)).toEqual({ password: true, links: 2, passkeys: 1 })
    expect(counts.get(b.id)).toEqual({ password: false, links: 1, passkeys: 0 })
    expect(counts.get(c.id)).toEqual({ password: false, links: 0, passkeys: 0 })
    expect(counts.get('no-such-account'), 'an unknown id answers zeros').toEqual({ password: false, links: 0, passkeys: 0 })
    expect(links.get('no-such-account'), 'an unknown id answers no links').toEqual([])
  })

  it('HONESTY: an empty request answers empty maps, never a throw', async () => {
    expect((await store.countSignInMethodsBulk([])).size).toBe(0)
    expect((await store.listIdentityLinksBulk([])).size).toBe(0)
  })
})
