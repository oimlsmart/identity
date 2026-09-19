# TODO.modern/01 — bot protection on the public credential surfaces (Turnstile)

**Priority:** P0 · **Status:** COMPLETE (2026-09-19)
**Doctrine:** config-gated (TURNSTILE_SITE_KEY + TURNSTILE_SECRET; unset = byte-identical posture), worker-safe (fetch + WebCrypto), the OCP mount alongside the rate limiter.

## What landed
- `server/auth/op/turnstile.ts` — the verify seam (siteverify, the remote IP rides along).
- `server/routes/op.ts` — the `turnstileGate` middleware on the login family, register, and the join submit (the same mount list as the rate limiter's public faces). The token rides the body (`cf-turnstile-response`).
- Refusal: 403 with the honest one-line error, BEFORE any credential work — never a 401 shape (no enumeration aid; a bot answer differs from an auth answer).
- Specs: the module (success/failure/unset), the route gate (403 on a bad token, pass-through on a good one, no-change when unset).

## The owner acts
`wrangler secret put TURNSTILE_SECRET --env identity` + the site key in [env.identity.vars] — until then, nothing changes.
