# TODO.modern/13 — the transport/document hardening baseline (security headers)

**Priority:** P1 · **Status:** IMPLEMENTED
The universally recommended headers the HTML/API surface lacked: HSTS,
nosniff, referrer-policy, and a default frame-deny with the one
deliberate exemption (the session-management iframe is framed BY the
RPs by design).

## What shipped
1. **An app-wide header seam** (first in the middleware stack, beside
   the request-id seam): every answer carries
   `X-Content-Type-Options: nosniff`; every HTML answer additionally
   carries `Strict-Transport-Security: max-age=31536000` (this host is
   TLS-only by construction; `includeSubDomains` deliberately omitted —
   the zone's subdomain policy is the owner's, not the app's to decree)
   and `Referrer-Policy: no-referrer` (the credential surface never
   leaks its referrers).
2. **Frame-deny by default, one honest exemption**: HTML answers carry
   `Content-Security-Policy: frame-ancestors 'none'` — EXCEPT answers
   that already carry a CSP (the check_session_iframe's own
   `frame-ancestors *` wins by design — the RPs frame it, RFC's
   session-management protocol). The middleware never overrides an
   existing header (the first-set-wins rule).
3. **No script-src CSP — named, not fumbled**: a real content CSP needs
   the Astro build's nonce story + Scalar's CDN script audit; locking
   it blind would break the console. Its own sized follow-up.
4. Specs (`id-sec-headers.test.ts`): the API answer (nosniff + no
   frame policy on JSON), the HTML answer (HSTS + nosniff +
   no-referrer + frame-ancestors 'none'), the session iframe's
   exemption (its `frame-ancestors *` stands), and the no-override rule.

**Open (honest):** the content CSP (script-src with the build's nonce
story) — its own brief when scheduled.
