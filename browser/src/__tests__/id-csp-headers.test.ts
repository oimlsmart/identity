// ─────────────────────────────────────────────────────────────────────
// The script-src CSP's build core (TODO.modern/19): the pure functions
// the postbuild step runs over the BUILT html — the distinct inline-
// script hashes, the managed _headers block, and the merge + the
// self-check (every executable inline script must be covered or the
// build fails). The live evidence: 75 inline scripts across the
// shells, 7 distinct hashes, build-stable.
// ─────────────────────────────────────────────────────────────────────

import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  cspDirectiveFor,
  inlineScriptHashes,
  managedBlock,
  mergeHeaders,
  uncoveredScripts,
} from '../../scripts/generate-csp-headers'

const FIXTURE = `<!doctype html><html><head>
<script type="importmap">{"imports":{"x":"/x.js"}}</script>
</head><body>
<script>console.log('the island bootstrap')</script>
<script type="module">const a = 1</script>
<script>console.log('the island bootstrap')</script>
<script src="/external.js"></script>
<script></script>
</body></html>`

describe('inlineScriptHashes', () => {
  it('hashes every EXECUTABLE inline script, distinct, in first-appearance order', () => {
    const hashes = inlineScriptHashes(FIXTURE)
    // 4 executable inline blocks (the bootstrap twice → one hash;
    // the empty script counts; the importmap is not executable; the
    // external src is not inline).
    expect(hashes).toHaveLength(3)
    // The empty script's hash is the sha256 of the empty string —
    // present, never special-cased.
    const emptyHash = `'sha256-${createHash('sha256').update('', 'utf8').digest('base64')}'`
    expect(hashes).toContain(emptyHash)
    // Deterministic order (first appearance).
    const bootstrap = hashes.find(h => h !== emptyHash && !h.includes(createHash('sha256').update('const a = 1', 'utf8').digest('base64')))
    expect(hashes.indexOf(bootstrap!)).toBeLessThan(hashes.indexOf(emptyHash))
  })

  it('the hash form is the CSP source-expression form (sha256-<base64>, unpadded-free)', () => {
    const [first] = inlineScriptHashes("<script>const a = 1</script>")
    expect(first).toMatch(/^'sha256-[A-Za-z0-9+/]+='$/)
  })
})

describe('the managed _headers block', () => {
  it('the directive carries the hashes + self, appended to the CSP-lite posture', () => {
    const block = managedBlock(["'sha256-Aaa='", "'sha256-Bbb='"])
    expect(block).toContain("script-src 'self' 'sha256-Aaa=' 'sha256-Bbb='")
    expect(block).toContain("frame-ancestors 'none'")
    expect(block).toContain('Strict-Transport-Security: max-age=31536000')
    expect(block).toContain('X-Content-Type-Options: nosniff')
    expect(block).toContain('Referrer-Policy: no-referrer')
  })

  it('mergeHeaders replaces an existing managed block, keeps the rest (the adapter rule survives)', () => {
    const existing = '/_astro/*\n  Cache-Control: public, max-age=31536000, immutable\n'
    const once = mergeHeaders(existing, managedBlock(["'sha256-Aaa='"]))
    expect(once).toContain('/_astro/*')
    expect(once).toContain("'sha256-Aaa='")
    const twice = mergeHeaders(once, managedBlock(["'sha256-Aaa='", "'sha256-Bbb='"]))
    expect(twice).toContain("'sha256-Bbb='")
    expect(twice.match(/script-src 'self'/g)).toHaveLength(1)
  })
})

describe('the self-check (the build fails on drift)', () => {
  it('uncoveredScripts answers the hashes a CSP would miss', () => {
    const hashes = inlineScriptHashes(FIXTURE)
    expect(uncoveredScripts(FIXTURE, hashes)).toHaveLength(0)
    expect(uncoveredScripts(FIXTURE, hashes.slice(1))).toHaveLength(1)
  })

  it('cspDirectiveFor composes the shell header line', () => {
    const line = cspDirectiveFor(["'sha256-Aaa='"])
    expect(line).toBe("frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; script-src 'self' 'sha256-Aaa='")
  })
})
