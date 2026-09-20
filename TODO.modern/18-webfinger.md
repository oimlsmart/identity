# TODO.modern/18 — WebFinger (RFC 7033): the federation's discovery front door

**Priority:** P2 · **Status:** IMPLEMENTED
Shipped: the route answers on id.oimlsmart.org (the acct + mailto
forms for this service's own domain answer the JRD with the issuer
link; a foreign domain 404s — the never-a-proxy posture), the specs
pin the four legs (`id-webfinger.test.ts`), the OpenAPI spec documents
the route, and the member guide's federation step zero (#144)
completed the acceptance line. Live proof 2026-09-21:
`acct:ada@id.oimlsmart.org` and `mailto:ada@id.oimlsmart.org` answer
200 with the issuer link; `@oimlsmart.org` (a different domain from
this endpoint's) answers 404 by design — the member's OWN instance
answers for its own mail domain, per the guide.

The OIML member-federation story's missing first step: an RP holding
`someone@oimlsmart.org` discovers the issuer without configuration.

## The acts
1. `GET /.well-known/webfinger?resource=acct:ada@oimlsmart.org` (also
   the plain-email resource form) — answers the JRD with the issuer
   link (`rel: http://openid.net/specs/connect/1.0/issuer` →
   `https://id.oimlsmart.org`). Only THIS service's domain answers —
   another domain's resource answers 404 (never a proxy, never an
   open resolver).
2. The account need not exist (WebFinger resolves the DOMAIN's issuer,
   not the mailbox — enumeration-safe by construction; the honest
   posture: the resource's domain decides, no account probing).
3. Discovery advertises nothing (WebFinger is not an OIDC discovery
   key); the OpenAPI spec documents the route; the member-deployment
   guide links it as the federation's step zero.
4. Specs: the acct form, the mailto/email form, the foreign-domain
   404, the JRD shape.

**Acceptance:** an RP discovers `id.oimlsmart.org` from an email
address with zero configuration — the runbook's Act-3-central story
gains its standard front door.
