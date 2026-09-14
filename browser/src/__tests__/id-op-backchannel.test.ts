// ─────────────────────────────────────────────────────────────────────
// The OP back-channel's Astro-guard tripwire (the 2026-09-14
// estate-wide SSO break): Astro's built-in origin check (security.
// checkOrigin, default ON) 403s every non-GET carrying a form content
// type whose Origin header is absent or foreign — EXACTLY the OIDC
// back-channel's shape: POST /op/token (the relying party's code
// exchange), /op/revoke, /op/introspect are server-to-server form
// posts, and a relying party's worker sends no Origin. With the guard
// on, every RP's SSO exchange died at the token endpoint with
// 'Cross-site POST form submissions are forbidden' while the node
// posture (the e2e stacks, the contract gate — Hono direct, no Astro
// pipeline) stayed green: a deployment-shape gap the live probe found.
//
// The guard's value HERE is nil by construction: the browser surface's
// state-changing endpoints speak CORS-gated JSON behind SameSite=Lax
// session cookies, and the OIDC endpoints authenticate by code+PKCE or
// client credentials — never by ambient authority. The config carries
// `security: { checkOrigin: false }`; this test is the tripwire that a
// config rewrite never silently re-enables it.
//
// The assertion reads the config FILE: the two type gates disagree on
// importing the .mjs (vue-tsc demands a declaration, astro check calls
// the directive unused) — the text pin is the stable contract.
// ─────────────────────────────────────────────────────────────────────

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CONFIG = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'astro.config.mjs')

describe('the OP back-channel posture (the origin-guard tripwire)', () => {
  it('the Astro config disables checkOrigin — the OIDC form endpoints answer server-to-server callers', () => {
    const text = readFileSync(CONFIG, 'utf-8')
    expect(text).toMatch(/security:\s*\{\s*checkOrigin:\s*false\s*\}/)
  })
})
