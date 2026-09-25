// ═══════════════════════════════════════════════════════════════════
// The script-src CSP's postbuild step (TODO.modern/19): the built
// shells carry their island-bootstrap scripts INLINE, so a strict
// script-src is only honest as BUILD-DERIVED HASHES — the same
// content every render, the hashes derived from the build itself, the
// build failing on any uncovered script (the drift tripwire is the
// build, never a stale allowlist).
//
//   generate-csp-headers.ts   (tsx, after `astro build`):
//     1. scan dist/client/**/*.html
//     2. hash every executable inline <script> (distinct, ordered)
//     3. merge the managed block into dist/client/_headers (the
//        adapter's own file — idempotent replace)
//     4. self-check: re-scan; any uncovered script fails the build
//
// The empty script's hash is present, never special-cased; importmaps
// are not executable and never hash.
// ═══════════════════════════════════════════════════════════════════

import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

/** The executable inline scripts' SHA-256 source expressions, distinct,
 *  first-appearance order. Non-executable types (importmap and
 *  friends) and external src references never hash. */
export function inlineScriptHashes(html: string): string[] {
  const hashes: string[] = []
  const seen = new Set<string>()
  const re = /<script([^>]*)>([\s\S]*?)<\/script>/g
  let m: RegExpExecArray | null
  while ((m = re.exec(html)) !== null) {
    const attrs = m[1] ?? ''
    if (/\bsrc\s*=/.test(attrs)) continue
    if (/\btype\s*=\s*["'](importmap|application\/json|text\/template)["']/.test(attrs)) continue
    const body = m[2] ?? ''
    const hash = sha256Sync(body)
    if (!seen.has(hash)) {
      seen.add(hash)
      hashes.push(`'sha256-${hash}'`)
    }
  }
  return hashes
}

/** Synchronous SHA-256 (node:crypto — the script runs under tsx, the
 *  node posture only; never imported by the worker graph). */
import { createHash } from 'node:crypto'
function sha256Sync(body: string): string {
  return createHash('sha256').update(body, 'utf8').digest('base64')
}

/** The shell CSP: the CSP-lite posture + the build-derived script-src.
 *  The analytics beacon's origin rides script-src: the zone's Web
 *  Analytics auto-injects the beacon into every HTML response, and the
 *  strict script-src would block it (the 2026-09-23 finding — the
 *  owner enabled analytics). */
export const ANALYTICS_BEACON_ORIGIN = 'https://static.cloudflareinsights.com'

export function cspDirectiveFor(hashes: string[]): string {
  return `frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; script-src 'self' ${hashes.join(' ')} ${ANALYTICS_BEACON_ORIGIN}`
}

const MANAGED_BEGIN = '# ── the script-src CSP (TODO.modern/19, generated — do not edit) ──'
const MANAGED_END = '# ── end generated ──'

/** The managed block: the security-header set for every asset
 *  response. The asset-specific rules (the /_astro/* immutable rule)
 *  live outside and win by specificity. */
export function managedBlock(hashes: string[]): string {
  return [
    MANAGED_BEGIN,
    '/*',
    `  Content-Security-Policy: ${cspDirectiveFor(hashes)}`,
    '  Strict-Transport-Security: max-age=31536000',
    '  X-Content-Type-Options: nosniff',
    '  Referrer-Policy: no-referrer',
    MANAGED_END,
    '',
  ].join('\n')
}

/** Idempotent merge: the managed block replaces itself, everything
 *  else (the adapter's /_astro/* rule) survives untouched. */
export function mergeHeaders(existing: string, block: string): string {
  const begin = existing.indexOf(MANAGED_BEGIN)
  if (begin === -1) return existing.replace(/\n*$/, '\n\n') + block
  const end = existing.indexOf(MANAGED_END, begin)
  if (end === -1) return existing.replace(/\n*$/, '\n\n') + block
  return existing.slice(0, begin) + block + existing.slice(end + MANAGED_END.length).replace(/^\n+/, '\n')
}

/** The build's tripwire: the hashes a CSP would miss. */
export function uncoveredScripts(html: string, covered: string[]): string[] {
  return inlineScriptHashes(html).filter(h => !covered.includes(h))
}

// ── the CLI (tsx scripts/generate-csp-headers.ts) ──
const isMain = process.argv[1]?.endsWith('generate-csp-headers.ts')
if (isMain) {
  const dist = join(process.cwd(), 'dist', 'client')
  if (!existsSync(dist)) {
    console.error('[csp-headers] dist/client does not exist — run the astro build first')
    process.exit(1)
  }

  const htmlFiles: string[] = []
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, entry.name)
      if (entry.isDirectory()) walk(p)
      else if (entry.name.endsWith('.html')) htmlFiles.push(p)
    }
  }
  walk(dist)

  const all = new Set<string>()
  for (const file of htmlFiles) {
    for (const hash of inlineScriptHashes(readFileSync(file, 'utf8'))) all.add(hash)
  }
  const hashes = [...all].sort()
  console.log(`[csp-headers] ${htmlFiles.length} html files, ${hashes.length} distinct inline-script hashes`)

  const headersPath = join(dist, '_headers')
  const existing = existsSync(headersPath) ? readFileSync(headersPath, 'utf8') : ''
  const merged = mergeHeaders(existing, managedBlock(hashes))
  writeFileSync(headersPath, merged)

  // The self-check: every html file's scripts must be covered by the
  // emitted directive (a re-read of the WRITTEN file — the proof is
  // the artifact, not the intention).
  const written = readFileSync(headersPath, 'utf8')
  const directive = written.split('\n').find(l => l.includes('script-src'))
  let uncovered = 0
  for (const file of htmlFiles) {
    for (const miss of uncoveredScripts(readFileSync(file, 'utf8'), hashes)) {
      uncovered++
      console.error(`[csp-headers] UNCOVERED ${miss} in ${file}`)
    }
  }
  if (!directive?.includes('script-src') || uncovered > 0) {
    console.error('[csp-headers] the self-check FAILED — the build is red')
    process.exit(1)
  }
  console.log(`[csp-headers] ${headersPath} written; the self-check passed`)
}
