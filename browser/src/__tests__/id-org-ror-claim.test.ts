// ─────────────────────────────────────────────────────────────────────
// TODO.sota/05 — the org_ror claim: the account's active org's ROR id
// rides the token only per the client's policy (the same privilege
// gate as the role claims), absent without a matched id.
// ─────────────────────────────────────────────────────────────────────
import { describe, expect, it } from 'vitest'
import { orgRorClaimForClient } from '../../server/auth/op/claims'

const store = (rows: Record<string, { rorId: string | null }>) => ({
  getOrgRegistryOrg: async (id: string) => rows[id] ?? null,
})

describe('the org_ror claim (TODO.sota/05)', () => {
  it('gated by the policy AND the registry row — absent otherwise, never a placeholder', async () => {
    const policy = { claims: ['org_ror'] }
    const st = store({ 'nist.gov': { rorId: 'https://ror.org/05xpvk416' }, 'abnorm.bf': { rorId: null } })
    expect(await orgRorClaimForClient(st, 'nist.gov', policy)).toBe('https://ror.org/05xpvk416')
    expect(await orgRorClaimForClient(st, 'abnorm.bf', policy)).toBeNull()
    expect(await orgRorClaimForClient(st, 'unknown.org', policy)).toBeNull()
    expect(await orgRorClaimForClient(st, 'nist.gov', { claims: ['org'] })).toBeNull()
    expect(await orgRorClaimForClient(st, 'nist.gov', null)).toBeNull()
    expect(await orgRorClaimForClient(st, null, policy)).toBeNull()
  })
})
