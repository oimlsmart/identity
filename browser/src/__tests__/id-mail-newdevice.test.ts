// ─────────────────────────────────────────────────────────────────────
// TODO.modern/06's notice half — the sign-in mail's NEW DEVICE line:
// the first sighting of a (UA, IP) pair adds the advisory sentence to
// the 'signin' notice (the resetUrl conditional's precedent — a
// template-scoped block, present only when the flag rides). EN/FR
// lockstep; absent flag = the mail byte-shape unchanged.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import { renderOpMail } from '../../server/auth/op/mail'

const BASE = { name: 'Ada', when: '2026-09-19 12:00', method: 'password', product: 'OIML SMART Identity', locale: 'en' }

describe('the sign-in notice\'s new-device line', () => {
  it('rides the mail when the flag is set (EN + FR)', () => {
    const en = renderOpMail('signin', 'en', { ...BASE, newDevice: true })
    expect(en.text).toContain('not used before')
    const fr = renderOpMail('signin', 'fr', { ...BASE, newDevice: true })
    expect(fr.text).toContain('jamais utilis')
  })

  it("is ABSENT without the flag — the mail's shape unchanged", () => {
    const en = renderOpMail('signin', 'en', BASE)
    expect(en.text.toLowerCase()).not.toContain('not used before')
    expect(en.html.toLowerCase()).not.toContain('not used before')
  })

  it('carries into the HTML part too (the styled advisory)', () => {
    const en = renderOpMail('signin', 'en', { ...BASE, newDevice: true })
    expect(en.html).toContain('not used before')
  })
})
