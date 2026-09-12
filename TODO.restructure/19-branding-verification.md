# TODO.restructure/19 — branding verification

**Priority:** P0 (the owner's ask: "verify branding works") · **Status:**
COMPLETE (server-side + config layer; the browser-layer proof rides CI)

## What landed

`id-whitelabel.test.ts` proves the brand projection end-to-end
server-side: every declared field (name, logo paths, tagline) rides
/api/config verbatim; undeclared fields ride ABSENT (branding.ts's
merge keeps the service defaults client-side — the two halves compose);
the whitelabel console answers exactly its declared set. The flavor
profiles exercise the fields for real. The BROWSER render proof
(logo swap on the live page) rides the e2e pack in CI — this machine
cannot boot legs (the astro-lock doctrine, TODO 09); the closest local
proof is the config + merge contract above.
