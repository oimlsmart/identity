// ─────────────────────────────────────────────────────────────────────
// The sign-in panel feed (server/app.ts's /api/panels + the client's
// selection semantics), the ISO-benchmark structural item 4:
//
//   the route — serves the committed document as JSON, cached briefly
//     (public, max-age=300), no auth;
//   the document — every panel's copy is EN/FR lockstep (badge, heading,
//     body, the CTA label when carried), dates parse date-only;
//   the selection — enabled + inside the window (inclusive), priority
//     descending, the daily rotation deterministic modulo the eligible
//     set, an empty eligible set honestly NO panel;
//   the offline default — the client's bundled fallback IS the served
//     document (one file, imported both sides — drift-free).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-signin-panels-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

import feed from '../../server/signin-panels.json'
import { eligiblePanels, pickPanel, localizePanel, type SigninPanel, type SigninPanelFeed } from '../signin-panels'

let app: import('hono').Hono

beforeAll(async () => {
  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  installSqliteStore()
  const { parseInstanceProfile } = await import('@oimlsmart/platform-server/profile')
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({
    autoSeedDemo: false,
    instanceProfile: parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: false
`),
  })
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
})

const DAY = 86_400_000
const DAY0 = Date.UTC(2026, 7, 31) // a fixed UTC midnight

function panel(partial: Partial<SigninPanel> & { id: string; priority: number }): SigninPanel {
  return {
    enabled: true,
    startDate: null,
    endDate: null,
    content: {
      badge: { en: `${partial.id} badge`, fr: `${partial.id} insigne` },
      heading: { en: `${partial.id} heading`, fr: `${partial.id} titre` },
      body: { en: `${partial.id} body`, fr: `${partial.id} corps` },
      cta: null,
    },
    ...partial,
  }
}

describe('the sign-in panel feed', () => {
  it('the route serves the committed document, cached briefly', async () => {
    const res = await app.request('http://op.test/api/panels')
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
    const body = (await res.json()) as SigninPanelFeed
    expect(body.version).toBe(feed.version)
    expect(body.panels.length).toBeGreaterThanOrEqual(1)
    // The first panel is the passkey promotion (the benchmark's brief:
    // ours exist — ISO's mfa-promotion panel, answered).
    expect(body.panels[0]!.id).toBe('passkeys')
    expect(body.panels[0]!.enabled).toBe(true)
  })

  it('the committed document is EN/FR lockstep with parseable dates', () => {
    // The JSON import types cta as its literal null — read through the
    // interface so the optional-CTA checks typecheck.
    for (const p of feed.panels as unknown as SigninPanel[]) {
      for (const copy of [p.content.badge, p.content.heading, p.content.body]) {
        expect(copy.en?.trim(), `${p.id} en`).toBeTruthy()
        expect(copy.fr?.trim(), `${p.id} fr`).toBeTruthy()
      }
      if (p.content.cta) {
        expect(p.content.cta.label.en?.trim()).toBeTruthy()
        expect(p.content.cta.label.fr?.trim()).toBeTruthy()
        expect(p.content.cta.href).toMatch(/^\//)
      }
      for (const d of [p.startDate, p.endDate]) {
        if (d != null) expect(d, `${p.id} date`).toMatch(/^\d{4}-\d{2}-\d{2}$/)
      }
    }
  })

  it('selection: disabled and out-of-window panels never render', () => {
    const f: SigninPanelFeed = {
      version: 't',
      panels: [
        panel({ id: 'off', priority: 99, enabled: false }),
        panel({ id: 'future', priority: 90, startDate: '2027-01-01' }),
        panel({ id: 'past', priority: 80, endDate: '2026-01-01' }),
        panel({ id: 'live', priority: 10 }),
      ],
    }
    expect(eligiblePanels(f, DAY0).map((p) => p.id)).toEqual(['live'])
    // The window edges are inclusive.
    const edged: SigninPanelFeed = {
      version: 't',
      panels: [panel({ id: 'edged', priority: 1, startDate: '2026-08-31', endDate: '2026-08-31' })],
    }
    expect(eligiblePanels(edged, DAY0).map((p) => p.id)).toEqual(['edged'])
    expect(pickPanel(edged, DAY0 + DAY)).toBeNull() // an empty set is NO panel
  })

  it('selection: priority orders, the day index rotates deterministically', () => {
    const f: SigninPanelFeed = {
      version: 't',
      panels: [panel({ id: 'low', priority: 5 }), panel({ id: 'high', priority: 20 }), panel({ id: 'mid', priority: 10 })],
    }
    expect(eligiblePanels(f, DAY0).map((p) => p.id)).toEqual(['high', 'mid', 'low'])
    const seq = [0, 1, 2, 3].map((d) => pickPanel(f, DAY0 + d * DAY)!.id)
    expect(seq).toContain('high')
    expect(new Set(seq).size).toBe(3) // every panel gets its day
    expect(seq[0]).toBe(seq[3]) // deterministic modulo the set size
  })

  it('localization: the active locale wins, English falls back per field', () => {
    const p = panel({ id: 'x', priority: 1 })
    p.content.body = { en: 'english only' } as Record<string, string>
    const fr = localizePanel(p, 'fr')
    expect(fr.heading).toBe('x titre')
    expect(fr.body).toBe('english only')
    expect(localizePanel(p, 'en').badge).toBe('x badge')
  })
})
