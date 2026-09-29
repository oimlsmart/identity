// ─────────────────────────────────────────────────────────────────────
// TODO.sota/05 — the ORCID claim: the linked iD rides the token only
// per the client's policy (the same privilege gate as the role
// claims), absent without a link.
// ─────────────────────────────────────────────────────────────────────
import { describe, expect, it } from 'vitest'
import { orcidClaimForClient } from '../../server/auth/op/claims'

const store = (links: Array<{ provider: string; providerAccountId: string }>) => ({
  listIdentityLinks: async () => links,
})

describe('the orcid claim (TODO.sota/05)', () => {
  it('gated by the policy AND the link — absent otherwise, never a placeholder', async () => {
    const policy = { claims: ['orcid'] }
    expect(await orcidClaimForClient(store([{ provider: 'orcid', providerAccountId: '0000-0002-1825-0097' }]), 'u1', policy)).toBe('0000-0002-1825-0097')
    expect(await orcidClaimForClient(store([{ provider: 'google', providerAccountId: 'g-1' }]), 'u1', policy)).toBeNull()
    expect(await orcidClaimForClient(store([{ provider: 'orcid', providerAccountId: '0000-0002-1825-0097' }]), 'u1', { claims: ['roles'] })).toBeNull()
    expect(await orcidClaimForClient(store([{ provider: 'orcid', providerAccountId: '0000-0002-1825-0097' }]), 'u1', null)).toBeNull()
  })
})
