# TODO.modern/04 — the SAML upstream bridge (the members' national IdPs)

**Priority:** P1 · **Status:** HELD (the XML-DSig choice is a named-risk decision)
An upstream provider of kind `saml`: the metadata import, the redirect POST binding, the assertion validation, the link model identical to OIDC upstreams.

## The acts
1. The provider row's kind `saml` + the metadata (IdP entity ID, SSO URL, the X.509 cert) — config via OP_UPSTREAM_SEED's SAML shape or the console.
2. The SP side: our metadata endpoint (`/op/upstream/saml/metadata`), the signed AuthnRequest redirect, the ACS endpoint (`/op/upstream/saml/acs`).
3. Assertion validation: signature (XML-DSig), audience (our entity ID), InResponseTo, the clock skew bound, the Subject/NameID → the link key (provider + NameID).
4. The link model: EXACTLY the OIDC upstream's (identity_links; the honest unlinked refusal; never email-alone).
5. Worker-safety: XML validation in pure TS (no node builtins) — the cryptography rides WebCrypto (X509 verify is the hard part; vet a WASM/TS XML-DSig implementation carefully, that choice is this TODO's risk).
6. Specs: the metadata import, a signed assertion round-trip (the fixture generator), the link refusal, the clock-skew refusal; e2e: the SAML leg boots a fixture IdP.

**Acceptance:** a member's national IdP metadata configures sign-in; the e2e proves the dance.

**Why held:** the brief itself names the risk — assertion validation needs an
XML-DSig implementation that is worker-safe (WebCrypto/X.509), and vetting that
choice (a WASM or pure-TS library, its supply chain, its interop record) is a
decision that deserves its own focused PR, not a slice of a batch. The link
model, the metadata shape, and the ACS route design are already fixed by this
brief — implementation can start the moment the crypto choice is made.
