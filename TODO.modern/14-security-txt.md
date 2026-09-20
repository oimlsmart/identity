# TODO.modern/14 — the disclosure pointer + the index hygiene

**Priority:** P2 · **Status:** IMPLEMENTED
The RFC 9116 `security.txt` every security-conscious service serves,
and the credential surface's `noindex` default.

## What shipped
1. **`/.well-known/security.txt`** (RFC 9116): the disclosure contact
   is the repository's private security advisories — the real,
   monitored channel for this estate (never an invented mailbox) —
   with the yearly expiry (refreshed at the deploy review),
   `Preferred-Languages: en, fr`, the canonical URL, and the policy
   pointer (`docs/deployment/identity.md`). Documented in the OpenAPI
   spec (the drift gate holds; the SDK regenerated). Spec:
   `id-securitytxt.test.ts` (the RFC field shapes).
2. **The index hygiene**: IdShell (the shared shell) defaults the
   console + credential pages to `noindex, nofollow` — the account
   consoles, the setup/consent/join flows never leak into search
   indexes. The LANDING (the sign-in page — the service's public front
   door) opts into `index, follow` via the new `indexable` prop; the
   api-docs page keeps its own explicit `index, follow`.

**Open (honest):** nothing named beyond the standing frontier (DPoP,
the content-CSP nonce story, the conformance run's host, the bridge).
