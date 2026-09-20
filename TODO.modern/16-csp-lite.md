# TODO.modern/16 — the CSP-lite directives + COOP (the header story's completion)

**Priority:** P2 · **Status:** IMPLEMENTED
The four hardening directives that do NOT depend on the static shells'
script story — each kills a real attack class on its own.

## What shipped
1. **CSP-lite on the HTML answers** (joining the shipped
   frame-ancestors): `object-src 'none'` (the plugin/embed vector),
   `base-uri 'self'` (the <base>-hijack class — an injected base tag
   rewrites every relative URL on the page), `form-action 'self'`
   (form hijack/exfiltration — every form on this service posts to
   itself). `script-src` deliberately ABSENT — the prerendered shells'
   inline island scripts make any script-src either broken or
   `unsafe-inline` theater; the honest story stays named in
   TODO.modern/13 (it needs the SSR/nonce architecture).
2. **`Cross-Origin-Opener-Policy: same-origin`** on the HTML answers:
   the opener isolation for the login flows — no cross-origin opener
   relationship this service relies on (the RPs arrive by REDIRECT,
   not window.open; response_mode=popup is not served).
3. The seam: the same first-set-wins middleware (TODO.modern/13's) —
   the frame-ancestors line becomes the full CSP string; the check
   iframe's own frame-ancestors * still wins by design (it carries no
   CSP-lite — an IFRAME needs no opener policy, and its framing is
   the point).
4. Specs: `id-sec-headers.test.ts` extended — the HTML answers carry
   the four directives + COOP; the iframe's exemption unchanged; the
   API answers stay header-clean (JSON frames nothing, opens nothing).

**Open (honest):** the script-src story (13's named architectural
item) — unchanged.
