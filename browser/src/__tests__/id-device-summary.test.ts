// ─────────────────────────────────────────────────────────────────────
// The security notices' device line (2026-10-13, the GitHub/Google
// parity): the summarized UA reads in the holder's vocabulary, unknown
// agents summarize honestly, and the notice templates carry the
// context through the renderer.
// ─────────────────────────────────────────────────────────────────────
import { describe, expect, it } from 'vitest'

describe('deviceSummary', () => {
  it('summarizes the common agents into the holder’s vocabulary', async () => {
    const { deviceSummary } = await import('../../server/auth/op/device-summary')
    expect(deviceSummary('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36')).toBe('Chrome on macOS')
    expect(deviceSummary('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/127.0')).toBe('Firefox on Windows')
    expect(deviceSummary('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile Safari/604.1')).toBe('Safari on iOS')
    expect(deviceSummary('Mozilla/5.0 (X11; Linux x86_64) Edg/126.0')).toBe('Edge on Linux')
  })
  it('summarizes honestly when nothing matches', async () => {
    const { deviceSummary } = await import('../../server/auth/op/device-summary')
    expect(deviceSummary('curl/8.4.0')).toBe('an unrecognized browser')
    expect(deviceSummary('')).toBe('an unrecognized client')
    expect(deviceSummary(null)).toBe('an unrecognized client')
  })
})
