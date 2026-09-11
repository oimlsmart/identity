// ─────────────────────────────────────────────────────────────────────
// TODO.restructure/17+19 — the whitelabel posture (a): the profile-driven
// brand + console projection, proven in-process over the REAL app
// factory (the id-self-registration harness posture):
//
//   THE BRAND   a custom-profile instance projects its OWN name, logo
//               paths, and tagline through /api/config — every field
//               the profile declares rides, undeclared fields keep the
//               identity service's own defaults (the client merges);
//   THE CONSOLE the declared section set narrows the admin rail's data
//               (the projection answers exactly the declared keys);
//               an UNDECLARED console answers null — the full default
//               set (the central instance's posture, byte-compatible);
//   THE GATE    a profile naming an UNKNOWN section key fails LOUDLY
//               at parse (a typo never narrows a console silently).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-whitelabel-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://ia.example'
process.env.OP_ISSUER = ISSUER

import { installSqliteStore } from '../../server/store/sqlite'

let app: import('hono').Hono
let resetProfile: () => void
let installProfile: (yaml: string) => void
let parseProfile: typeof import('../../server/profile').parseInstanceProfile

const IA_PROFILE = `
identity:
  org_id: ex-ia
  org_name: Example Issuing Authority
  role_codes: [ia]
  country: FR
roles: [identity]
branding:
  name: Example IA Sign-In
  logo_light: /tenant/ia-logo-light.svg
  login_tagline: The Example Issuing Authority's single sign-on
demo_personas: false
console:
  sections: [overview, registry, users]
`

beforeAll(async () => {
  const profileMod = await import('../../server/profile')
  parseProfile = profileMod.parseInstanceProfile
  installProfile = (yaml: string) => profileMod.installInstanceProfile(profileMod.parseInstanceProfile(yaml))
  resetProfile = () => profileMod.resetInstanceProfileForTest()
  installSqliteStore()

  const { Hono } = await import('hono')
  const { createApiApp } = await import('../../server/app')
  app = new Hono()
  app.route('/', createApiApp({ autoSeedDemo: false }))
})

afterAll(() => {
  resetProfile()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
})

describe('TODO.restructure/17 — the whitelabel profile', () => {
  it('THE BRAND: /api/config projects every declared field, defaults otherwise', async () => {
    installProfile(IA_PROFILE)
    const res = await app.request(`${ISSUER}/api/config`)
    expect(res.status).toBe(200)
    const cfg = await res.json() as {
      branding: Record<string, unknown>
      console: { sections: string[] } | null
    }
    expect(cfg.branding.productName).toBe('Example IA Sign-In')
    expect(cfg.branding.logoLight).toBe('/tenant/ia-logo-light.svg')
    expect(cfg.branding.loginTagline).toBe('The Example Issuing Authority\'s single sign-on')
    // Undeclared fields ride ABSENT (the service's own defaults live
    // client-side in branding.ts — the merge's other half).
    expect(cfg.branding.markLight).toBeUndefined()
    // The whitelabel console answers exactly its declared set.
    expect(cfg.console).toEqual({ sections: ['overview', 'registry', 'users'] })
  })

  it('UNDECLARED: no console section answers null — the central posture unchanged', async () => {
    installProfile(`
identity:
  org_id: central
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
`)
    const cfg = await (await app.request(`${ISSUER}/api/config`)).json() as { console: unknown }
    expect(cfg.console).toBeNull()
  })

  it('TODO.restructure/23 — the platform residue is gone: configuration, never hardcoding', async () => {
    const profileMod = await import('../../server/profile')
    // The fallback default is the IDENTITY service's own — never a platform posture.
    const fallback = profileMod.defaultInstanceProfile()
    expect(fallback.roles).toEqual(['identity'])
    expect(fallback.branding.name).toBe('OIML SMART Identity')
    expect(fallback.identity.org_id).toBe('oimlsmart-id')
    expect(fallback.modules).toEqual(['identity'])
    // The catalog carries identity's OP surface alone.
    expect([...profileMod.INSTANCE_MODULES]).toEqual(['identity'])
    // A platform posture is refused loudly — this service is an OP deployment.
    expect(() => parseProfile(`
identity:
  org_id: biml
  org_name: BIML
  role_codes: [hub]
roles: [hub]
`)).toThrow(/roles must be exactly \[identity\]/)
    // The org's participant kind (role_codes) remains the ORG's fact —
    // the whitelabel flavors' shape parses and projects.
    const ia = parseProfile(IA_PROFILE)
    expect(ia.roles).toEqual(['identity'])
    expect(ia.identity.role_codes).toEqual(['ia'])
    expect(profileMod.projectModuleToggles(ia)).toEqual({ identity: true })
    // The implicit seed is the demo cast ONLY — no derived staff.
    expect(profileMod.seedAccountsForProfile({ ...ia, demoPersonas: false })).toEqual([])
    expect(profileMod.seedAccountsForProfile({ ...ia, demoPersonas: true })).toEqual(await import('../../server/store').then(m => m.DEMO_ACCOUNTS))
  })

  it('THE GATE: an unknown section key fails the parse loudly', () => {
    expect(() => parseProfile(`
identity:
  org_id: ex-ia
  org_name: Example IA
  role_codes: [ia]
roles: [identity]
console:
  sections: [overview, not-a-section]
`)).toThrow(/not one of the known admin sections/)
  })
})
