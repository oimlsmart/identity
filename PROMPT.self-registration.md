# PROMPT — self-registration for Ommisa members, gated by the member-domains registry

The Ommisa assistant opens its member tier to self-registration. A new
user picks their **country**, then their **organization**, then registers
with an email address **on that organization's stated domain**. The
registry that defines the eligible countries, organizations and domains
is built and maintained in `~/src/oimlsmart/member-domains/`
(`registry/web-domains.yaml`, flat rows of
`{ country, org, domain, website, source, note?, checked_at }`, every
row sourced). This repository — the identity service — implements the
enrollment that consumes it. Work additively: the admin-issued invite
path, the join-request queue, and every existing surface stay untouched.
All changes ride a pull request; nothing deploys without the owner's
explicit word. No AI attribution anywhere.

## 1. The registry in the service

- Parse `web-domains.yaml` at build time into a read-only projection:
  `countries: [{ name, orgs: [{ name, domains: [lowercase…] } ] }]`
  (dedupe organizations by token-set match — the file's header notes
  one duplicated "(BELGIM)" pair; merge, don't multiply).
- Serve it to the enrollment page from the worker (a bundled asset or a
  compressed config var — never a runtime fetch of the member-domains
  repo). A `checked_at` summary rides the payload for the audit entry.
- The matcher is exact-or-dot-suffix on lowercase: an email matches an
  organization when its domain equals an entry or ends with `"." +
  entry`. `nist.gov.example.com` never matches `nist.gov`. Free-mail and
  disposable providers match nothing, by construction.

## 2. The surface and the endpoint

- The sign-in page gains "Create your account": two pickers (country,
  then that country's organizations) and the email/name/password fields,
  behind the existing Turnstile module.
- `POST /api/op/self-register` validates **in this order**: the kill
  switch (`OP_SELF_REGISTER`, default on) → Turnstile → rate caps (a
  sliding 10 new accounts per IP per day, 5 per domain per day) → the
  country exists → the organization belongs to it → the email's domain
  matches that organization under the dot-boundary rule → the email is
  not already registered. Every rejection explains itself in a complete
  sentence and states the admin-queue alternative where it applies.
- When the domain matches a DIFFERENT organization in the registry, the
  error names it: "this domain is registered to <org> — choose it from
  the organization list."

## 3. The provisioning (the existing seam, reused verbatim)

An accepted registration provisions exactly what an admin-approved
invite provisions: `createOpAccount` (provider `password`), the
organization binding, the member role set, and the one-time 24-hour
setup link (`mintEnrollmentToken` + `enrollment_tokens`), emailed when
the mail provider is configured and shown once otherwise. The country
and organization pickers are **eligibility gates, not org bindings**:
self-registered members bind to the org the configuration names
(`OP_SELF_REGISTER_ORG`) with the roles it names
(`OP_SELF_REGISTER_ROLES`), so the estate's org model stays deliberate.
The member tier (300 questions a day) applies to these accounts
unchanged — the AI service's metering needs no change. The audit chain
records the enrollment with the registry row's `checked_at`.

## 4. The queue fallback

A domain the registry does not hold gets the join-request queue the
service already operates — the request is created, the applicant sees a
complete sentence saying an administrator will review it, and `cs_admin`
decides on the existing surface. No new state, no new schema.

## 5. `prompt=none` (the SSO completion, same service)

The authorize endpoint currently redirects a sessionless `prompt=none`
request to the login page. Make it OIDC-correct: when `prompt=none` and
no live session covers the request, answer the client's `redirect_uri`
with `error=login_required` (with `state`) instead of the login page.
Clients that probe silently — the Ommisa application's boot probe does —
then land anonymous cleanly, and the full-page login never flashes.

## 6. The tests

Worker-safe unit suites (the store seam, no node built-ins): the
dot-boundary matcher (exact, subdomain, the spoof case, the free-mail
case); the validation order (the kill switch beats Turnstile; the
domain check precedes provisioning); the rate caps; the queue fallback;
the `prompt=none` contract. An e2e walks the happy path — country,
organization, email on the stated domain, the setup link consumed — and
the two rejection paths.

## 7. The definition of done

A member of an OIML member state's authority, holding an address on the
authority's stated domain, creates their account in under a minute with
no human in the loop and signs in to Ommisa at the member tier. An
industry applicant lands in the queue with a clear sentence. A
sessionless `prompt=none` probe returns `login_required`. The invite
path, the join-request queue and every existing surface behave exactly
as before.
