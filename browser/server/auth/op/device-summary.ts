// ═══════════════════════════════════════════════════════════════════
// The security notices' device line (2026-10-13, the GitHub/Google
// parity pass): every "was this you" notice names WHAT and WHERE the
// act came from, in the holder's vocabulary — the browser on the
// platform, not the raw user-agent string. A summarized UA is honest
// about its coarseness: unknown agents read as "an unrecognized
// browser", never a guess.
//
// WORKER-SAFE: string work only.
// ═══════════════════════════════════════════════════════════════════

const BROWSERS: ReadonlyArray<[RegExp, string]> = [
  [/Edg\//, 'Edge'],
  [/OPR\/|Opera/, 'Opera'],
  [/Chrome\//, 'Chrome'],
  [/Firefox\//, 'Firefox'],
  [/Safari\//, 'Safari'],
]

const PLATFORMS: ReadonlyArray<[RegExp, string]> = [
  [/iPhone|iPad/, 'iOS'],
  [/Android/, 'Android'],
  [/Mac OS X|Macintosh/, 'macOS'],
  [/Windows/, 'Windows'],
  [/Linux/, 'Linux'],
]

/** The notice's device line: "Chrome on macOS". An absent or
 *  unrecognizable agent summarizes honestly. */
export function deviceSummary(userAgent: string | null | undefined): string {
  const ua = (userAgent ?? '').trim()
  if (!ua) return 'an unrecognized client'
  const browser = BROWSERS.find(([re]) => re.test(ua))?.[1] ?? 'an unrecognized browser'
  const platform = PLATFORMS.find(([re]) => re.test(ua))?.[1]
  return platform ? `${browser} on ${platform}` : browser
}
