# The member's own identity service — deployment + federation with the official OIML identity

> FOR: OIML member states and corresponding members, and OIML-CS
> associated organizations (Issuing Authorities and Test Laboratories)
> that want their OWN identity service, federated with the official
> OIML identity service at `id.oimlsmart.org`.
>
> This page is the CONNECTIVE guide: it walks the whole arc and points
> into the specialized runbooks for each act's detail. It adds the two
> pieces that had no home: the member-state flavor and the federation's
> BOTH-SIDES procedure.

## The model, in one paragraph

Your identity service is your OWN instance of this software: your
domain, your registry, your accounts, your brand — a configuration
act, never a code fork (the whitelabel posture, `identity-whitelabel.md`).
Federation with the official service is then plain OIDC, in the
direction that fits you: **upstream federation** (your people sign in
WITH their official OIML identity — your instance is the relying
party, the official OP is the identity provider), or **peer
coexistence** (your instance is sovereign; official-identity holders
link their accounts the way GitHub linking works today,
`identity-upstreams.md`). Every kind starts from the same base; only
the profile flavor and the console sections differ.

## Act 1 — your instance (every kind)

Follow `identity-whitelabel.md` (the IA/TL walk-through; the acts are
identical for every kind) and `identity-self-host.md` for the deploy
posture itself (Node + SQLite, or Workers + D1 — the runbook is
proven by the `id-16-selfhost` e2e). The summary:

1. **The profile** — a YAML file declaring your organization's
   identity, branding, and the console sections you operate:
   - an **Issuing Authority** starts from `browser/profiles/ia.yaml`;
   - a **Test Laboratory** starts from `browser/profiles/tl.yaml`;
   - a **member state / corresponding member** uses the same shape
     with your own `identity.org_id` (your OIML registry id) and
     kind-appropriate sections — the parse accepts any org; the
     FLAVORS are starting points, not code branches. Point
     `INSTANCE_PROFILE` at your copy.
2. **The issuer + keys** — `OP_ISSUER` is YOUR domain; declare
   `OP_SIGNING_KEY` with it (a fresh ES256 pair; the rotation
   ceremony is `scripts/op-key-rotate.ts`).
3. **The first administrator** — `OP_ACCOUNT_SEED`; the bootstrap
   invite's one-time setup link lands in your boot log.
4. **Your relying parties** — `OP_CLIENT_SEED`: every service of
   yours that will sign people in through your instance.

## Act 2 — your registry

Your instance's organization registry is YOURS (it never sees the
official instance's data). Seed it from your national structure or the
OIML register export via `scripts/import-org-registry.ts`, or manage
it in your console. If you appear on the official register (you do —
that is what membership means), your registry entry and the official
one carry the same `org_id`: the identifier is the join, the rows are
sovereign.

## Act 3 — federation with `id.oimlsmart.org` (BOTH sides)

Upstream federation — your people sign in with their official OIML
identity — is two configuration acts, one on each side:

**Your side (the relying party).** Register the official OP as a
generic-OIDC upstream provider on your instance
(`identity-upstreams.md`, the `OP_UPSTREAM_SEED` declaration): the
official OP's discovery document
(`https://id.oimlsmart.org/.well-known/openid-configuration`), the
client pair you received in Act 3-central, and your callback URL.
Your people then see "Sign in with OIML identity" beside your local
password sign-in; an official identity resolves to a local account
only through an explicit link (the link-by-verified-email rule and
the honest `upstream_not_linked` refusal apply exactly as the
upstream model defines).

**The central side (the identity provider).** The official OIML
identity service must know your instance as a registered relying
party: the OIML identity operator registers your client (your
instance's callback URL and the client pair) on the official
deployment's client registry. **This is a request to the operator**
(today: the client-registry governance policy, `docs/deployment/
identity.md` → the client registry section; the future self-service
request queue is the policy's named roadmap) — write to the operator
with your callback URL; you receive a client id and secret pair,
declared on your side as the upstream's credentials.

**What flows.** The official OP's tokens carry the standard claims
(`sub`, `email` + `email_verified`, `name`, `org`, `roles`) — your
instance consumes them per the upstream model. What does NOT flow:
your registry, your accounts' credentials, your audit journal. The
federation is an authentication trust, never a data merger.

**Peer coexistence (the lighter option).** If you do not want
official-identity sign-in on your instance, deploy sovereign and
stop after Act 2. Interoperation then rides the claims: services
that accept both issuers simply see two providers (the multi-issuer
posture every OIDC RP library supports natively).

**Step zero — the address discovers the issuer (WebFinger, RFC 7033).**
Before any configuration, a relying party holding a bare email address
on this domain can discover the issuer with zero configuration:

```sh
curl 'https://id.oimlsmart.org/.well-known/webfinger?resource=acct:ada@id.oimlsmart.org'
```

The JRD answers the `http://openid.net/specs/connect/1.0/issuer` link
(`https://id.oimlsmart.org`) — the domain decides (any local part; the
mailbox is never probed), and a foreign domain's resource answers 404.
An RP implementing the standard discovery dance starts here; the
member's own instance serves the same endpoint for ITS domain when you
deploy this software.

## The verification leg

The federation wiring above is proven in this repo's test suite:
`id-whitelabel-federation.test.ts` boots TWO real instances (a
central OP and a tenant instance) and drives the full OIDC dance —
the tenant delegates to the central OP, the claims round-trip, the
org context flows. Your deployment's federation can be verified the
same way: your instance + a scratch central, or against the official
instance's public discovery document (`/api/openapi.json` documents
the machine surface).
