# TODO.modern/19 — the script-src CSP: the shells join the transport story

**Priority:** P1 · **Status:** IMPLEMENTED (2026-09-25; the generator,
the `_headers` managed block, and the build's uncovered-script tripwire
are live — verified on production: the served shells carry the full
header set, the analytics beacon's origin joined script-src (#186), and
the scheme guard's inline script auto-hashed at build (#191))

## The evidence (2026-09-22, the built dist + the live host)

1. **The shells carry NO security headers on production.** `GET
   https://id.oimlsmart.org/register/` answers `200 text/html` from the
   edge (`cf-cache-status: HIT`) with NO Content-Security-Policy, NO
   HSTS, NO nosniff, NO referrer-policy. The prerendered shells answer
   from the ASSETS path — the sec-headers middleware (server/app.ts)
   only ever covers the Hono app's OWN HTML answers (the authorize
   refusal, the check iframe). The id-sec-headers gate proved the
   latter; the shells were its blind spot.
2. **The inline-script population is tiny and stable.** The built
   shells (`dist/client/**/*.html`) carry 75 inline `<script>` blocks
   across every page — only **7 distinct SHA-256 hashes** (4 shared
   island-bootstrap scripts ×18 pages, 3 page-specifics, one of them
   empty). The scripts are build-stable: the same content every render
   (the island props ride DOM attributes, not scripts).

## The design: build-derived hashes in the asset headers

- **A postbuild step** (`scripts/generate-csp-headers.ts`, wired after
  `astro build` in `build:cloudflare`) scans the built HTML, computes
  the distinct inline-script hashes, and merges a managed `/*` block
  into `dist/client/_headers` (the adapter's own file — the merge is
  idempotent; the adapter regenerates it every build):

  ```
  /*
    Content-Security-Policy: frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; script-src 'self' 'sha256-…' (×N)
    Strict-Transport-Security: max-age=31536000
    X-Content-Type-Options: nosniff
    Referrer-Policy: no-referrer
  ```

  Asset responses (the /_astro/* immutable rule) keep their own line —
  the managed block is `/*`, the more specific rule wins for assets.
- **Why hashes, not nonces:** the shells stay prerendered and
  edge-cacheable. A per-response nonce requires dynamic HTML (or
  rewriting cached responses — a nonce reuse hazard). The hashes are
  derived from the build itself, so a new script auto-includes its
  hash — the build self-checks (every inline script must be covered or
  the build FAILS; the drift tripwire is the build, not a spec that
  needs dist at unit time).
- **The Hono-rendered HTML** (the authorize refusal, the check iframe)
  gains `script-src` too: their inline scripts are fixed literals —
  the refusal's scripts (if any) hash at module load; the check
  iframe's CSP (`frame-ancestors *` exemption unchanged) gains its own
  script's hash. A spec recomputes the hash from the SERVED html and
  asserts coverage (the id-sec-headers extension).
- **The generator's pure core is unit-tested** (a fixture html → the
  exact hash list; executable scripts only — `type="importmap"` and
  friends excluded).

## The deliberately unchanged

- No `default-src` (the minimal-tightening discipline: each directive
  lands because something specific closes, never as theater).
- The check iframe's `frame-ancestors *` exemption (the RFC's
  protocol) — unchanged; script-src is additive to it.
- The first-set-wins seam (server/app.ts) — the middleware never
  overrides an existing header.

## Acceptance

1. `build:cloudflare` emits `_headers` whose `/*` block's script-src
   covers EVERY inline script in the built html (the build fails
   otherwise).
2. The check iframe's CSP covers its own script (spec-proven).
3. No directive appears without closing something real (the review
   rule).
4. The gates + builds stay green; the deployed shells answer with the
   full header set (the post-deploy probe).

## The honest note

The `_headers` mechanism applies to ASSET responses; the platform
applies it on every serve (cache HITs included — the headers are
merged at the edge, not stored in the cache entry). The post-deploy
probe (step 4) is the proof.
