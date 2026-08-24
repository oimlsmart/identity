import type { Browser } from 'puppeteer'

// ─────────────────────────────────────────────────────────────────────
// The identity e2e harness — the slim copy (the extraction map's risk
// 6: the harness is COPIED from the smart monorepo, not shared, and the
// copies are licensed to drift).
//
// The moved legs boot their own port-isolated stacks and drive their
// own page flows, so the shared-suite machinery (the island-settle
// waits, the chunk-fetch guard, the demo loginAs, the calibration) did
// NOT cross: the legs that face the chunk-fetch flake class carry their
// own one-reload guard inline (the monorepo's id-04/id-05 pattern).
// What every leg shares is below: the delay primitive and the browser
// teardown that never lets a stuck renderer fail a green suite.
// ─────────────────────────────────────────────────────────────────────

export const delay = (ms: number) => new Promise(r => setTimeout(r, ms))

/**
 * Close the browser, force-killing the process if close() wedges. A stuck
 * renderer on teardown must never fail an otherwise-green suite (observed:
 * browser.close() hanging past the 120 s hookTimeout under load).
 */
export async function closeBrowser(browser: Browser | undefined) {
  if (!browser) return
  try {
    await Promise.race([browser.close(), delay(15_000)])
  } catch { /* teardown — never fail the suite on close */ }
  try {
    const proc = browser.process()
    if (proc && proc.exitCode === null && !proc.killed) proc.kill('SIGKILL')
  } catch { /* already gone */ }
}
