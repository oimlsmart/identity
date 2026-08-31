// ═══════════════════════════════════════════════════════════════════
// The sign-in panel feed, client half (the ISO-benchmark structural
// item 4, the visual-elevation wave's move 3): the editorial left
// panel's rotating content. The canonical document is
// server/signin-panels.json, served at GET /api/panels (cached briefly);
// THIS module imports the same document as the OFFLINE DEFAULT, so a
// failed or slow fetch never blanks the panel — the served feed and the
// fallback are one file, drift-free by construction.
//
// Selection (pickPanel): enabled + inside the schedule window (date-only,
// inclusive both ends), sorted by priority descending, rotating daily
// through the eligible set (the day index modulo the set — deterministic,
// no cookie, no randomness; ISO's "strategy: random" with a 1-day cookie
// tamed into something an e2e leg can assert). An empty eligible set is
// NO PANEL, honestly — the welcome block alone carries the panel.
// ═══════════════════════════════════════════════════════════════════
import { computed, shallowRef, type ComputedRef } from 'vue'
import { currentLocale, type Locale } from './i18n'
import defaultFeed from '../server/signin-panels.json'

export interface SigninPanelCopy {
  badge: Record<string, string>
  heading: Record<string, string>
  body: Record<string, string>
  cta?: { label: Record<string, string>; href: string } | null
}

export interface SigninPanel {
  id: string
  priority: number
  enabled?: boolean
  startDate?: string | null
  endDate?: string | null
  content: SigninPanelCopy
}

export interface SigninPanelFeed {
  version: string
  panels: SigninPanel[]
}

/** The panel's copy resolved for one locale (English fallback per field). */
export interface ResolvedPanel {
  id: string
  badge: string
  heading: string
  body: string
  cta: { label: string; href: string } | null
}

const DAY_MS = 86_400_000

/** A date-only window check: [startDate, endDate] inclusive, null = open. */
function inWindow(panel: SigninPanel, today: string): boolean {
  if (panel.startDate && today < panel.startDate) return false
  if (panel.endDate && today > panel.endDate) return false
  return true
}

/** The eligible panels, priority-weighted (descending; ties keep the
 *  document order). */
export function eligiblePanels(feed: SigninPanelFeed, now: number): SigninPanel[] {
  const today = new Date(now).toISOString().slice(0, 10)
  return feed.panels
    .filter((p) => p.enabled !== false && inWindow(p, today))
    .sort((a, b) => b.priority - a.priority)
}

/** The day's panel: the eligible set, priority-descending, rotated by the
 *  day index. Null when nothing is eligible — the panel renders the
 *  welcome block alone. */
export function pickPanel(feed: SigninPanelFeed, now: number): SigninPanel | null {
  const eligible = eligiblePanels(feed, now)
  if (eligible.length === 0) return null
  return eligible[Math.floor(now / DAY_MS) % eligible.length]!
}

/** Resolve a panel's copy for the locale (per-field English fallback —
 *  a feed row missing the French never renders the raw key). */
export function localizePanel(panel: SigninPanel, locale: Locale): ResolvedPanel {
  const pick = (copy: Record<string, string>) => copy[locale] ?? copy.en ?? ''
  return {
    id: panel.id,
    badge: pick(panel.content.badge),
    heading: pick(panel.content.heading),
    body: pick(panel.content.body),
    cta: panel.content.cta ? { label: pick(panel.content.cta.label), href: panel.content.cta.href } : null,
  }
}

/** The shallow structural check the served feed gets before it replaces
 *  the default: a panels array of rows carrying localized heading+body. */
function feedShapeOk(feed: unknown): feed is SigninPanelFeed {
  if (typeof feed !== 'object' || feed === null) return false
  const panels = (feed as SigninPanelFeed).panels
  return (
    Array.isArray(panels) &&
    panels.every(
      (p) =>
        typeof p?.id === 'string' &&
        typeof p?.priority === 'number' &&
        typeof p?.content?.heading?.en === 'string' &&
        typeof p?.content?.body?.en === 'string',
    )
  )
}

// The served feed, probed once (inflight-deduped — the same posture as
// branding.ts's /api/config probe). Null = the offline default stands.
const servedFeed = shallowRef<SigninPanelFeed | null>(null)
let probed = false
let inflight: Promise<void> | null = null

export function resolvePanels(): Promise<void> {
  if (probed) return Promise.resolve()
  if (inflight) return inflight
  inflight = (async () => {
    try {
      const res = await fetch('/api/panels', { credentials: 'include' })
      if (res.ok) {
        const feed: unknown = await res.json()
        if (feedShapeOk(feed)) servedFeed.value = feed
      }
    } catch {
      // Offline or a broken feed — the bundled default stands.
    } finally {
      probed = true
      inflight = null
    }
  })()
  return inflight
}

/** The panel for the current moment + locale (the served feed when the
 *  probe landed, else the bundled default). Null = render no feed block. */
export function useSigninPanel(): { panel: ComputedRef<ResolvedPanel | null> } {
  return {
    panel: computed(() => {
      const feed = servedFeed.value ?? (defaultFeed as SigninPanelFeed)
      const picked = pickPanel(feed, Date.now())
      return picked ? localizePanel(picked, currentLocale()) : null
    }),
  }
}

/** Test seam: force the served feed (null re-arms the probe). */
export function setPanelsForTest(feed: SigninPanelFeed | null): void {
  inflight = null
  probed = feed !== null
  servedFeed.value = feed
}
