# TODO.restructure/05 — applicant self-account creation (the public register path)

**Priority:** P0 (product logic — the audit's headline illogic)
**Status:** COMPLETE

## Problem

Today an applicant CANNOT create an account themselves: the OP's account
model is invite-only by doctrine (`browser/server/routes/op-accounts.ts:114`
— "enrollment is INVITE-ONLY (no open signup, ever)"), and the public join
intake only files an ASK that an administrator must approve before the
account exists. A person with no organization affiliation (a manufacturer
engineer before the org is endorsed, an auditor, a committee observer) has
NO way in at all — the join page requires picking a registered org. The
owner overrules the doctrine: applicants create their own accounts; the
organization binding stays gated exactly as it is.

## The design (the liability shield keeps standing)

`POST /api/op/register` — public, rate-limited (the OP rate limiter,
`server/app.ts`), input `{name, email, password}`:

1. policy + breach gate (the enroll route's own order: a refused password
   never touches state; an unreachable corpus accepts and arms the
   sign-in re-check);
2. `createOpAccount({role: 'viewer'})` — the OP's no-privilege default;
   NO org binding, NO client roles (those stay admin/org-admin gated);
3. `setPasswordHash`;
4. the mailbox proof: the kernel 'verify' link (`sendEmailVerification`,
   mail-only) — the account signs in immediately with `email_verified:
   false` (the honest claim doctrine, commit 907e206), the strong factors
   stay locked until the link completes;
5. audit `account.self_registered`;
6. the answer NEVER mints a session and never echoes the link.

No-mailer deployments answer 503 BEFORE the account is created (an
unprovable mailbox would strand the account in the unverified state with
no way out — the resend path's own doctrine).

Page: `/register` (the bare shell + island, the login page's "Create
account" link), EN/FR copy. The invite-only doctrine comment is rewritten
to name the two coexisting paths honestly.

## Acceptance

- Specs: `id-self-registration.test.ts` — the happy register→sign-in→
  verify-link→verified arc, the duplicate-email posture, the no-mailer
  503, the policy/breach refusals, the rate-limit mount.
- Gates: vue-tsc, astro check, vitest run, both builds, the OIDC-surface
  contract golden UNTOUCHED.
- Follow-up (P2, 09): the puppeteer e2e leg + ci.yml's leg list.
