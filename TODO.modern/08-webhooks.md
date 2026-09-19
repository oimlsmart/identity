# TODO.modern/08 — the outbound events (webhooks on the audit journal)

**Priority:** P2 · **Status:** IMPLEMENTED
RPs subscribe to account events — the journal already carries them; the delivery layer rides BESIDE it, never inside its write path.

## What shipped
1. **The signature** (`browser/server/webhooks/signature.ts`) — the Stripe
   posture: `Webhook-Signature: t=<ms>,v1=<hex>` where
   `v1 = HMAC-SHA256(secret, "t.body")`; the verifier's 300 s tolerance
   bounds replay; the constant-fold compare. Consumer-side verify proven
   in the specs.
2. **The event vocabulary** (`browser/server/webhooks/events.ts`) — the
   SSOT whitelist of JOURNAL ACTION NAMES verbatim (never a translation
   layer): `account.password`, `account.session_revoked`,
   `account.pat_minted`, `account.pat_revoked`, `factor.totp_enrolled`,
   `factor.passkey_enrolled`. State CHANGES only — the password-reset
   REQUEST deliberately carries no delivery. Adding a deliverable act =
   one string + one emission line (the OCP extension).
3. **The subscription surface** (`browser/server/routes/op-webhooks.ts`,
   session-gated): list (active only, NEVER the secret), subscribe
   (https + literal public-host guards; the `oswh_` shared secret answers
   ONCE — plaintext-stored BY DESIGN: we sign with it, the subscriber
   verifies with their copy; it is never a credential presented to us),
   unsubscribe (owner-guarded deactivation), the delivery log.
4. **The delivery** (`browser/server/webhooks/deliver.ts`) —
   fire-and-forget at the act (`emitWebhookEvent`, waitUntil on the
   Worker, the honest swallowed catch on node); the bounded ladder
   (3 attempts, 0/1s/5s — `WEBHOOK_RETRY_DELAYS_MS` overridable); the
   dead-letter record (attempts + last status + the body's SHA-256
   digest ONLY — privacy + size). The fan-out reads the account's
   subscriptions ONCE per event, SQL-narrowed (migration 0029 +
   schema.sql in lockstep — the migrations test pins it).
   **MECE note:** the emission sits at the six ACT SITES (the routes),
   never inside the journal's write path — the store stays
   delivery-agnostic.
5. **The store**: `webhook_subscriptions` + `webhook_deliveries` (both
   backends — the sqlite module + the D1 methods with the
   ensure-lazy-tables posture; account-narrowed indexes; the delivery
   path never scans the table).
6. **Documented** in the OpenAPI spec (the drift gate holds — the
   Webhooks tag). Specs: `src/__tests__/id-webhooks.test.ts` (12) —
   the signature trio, the whitelist, the CRUD postures (the secret
   ONCE, https/private-host refusals, the owner guard), the delivery
   (signed + envelope-shaped + recorded), the ladder's dead letter, and
   the fan-out at a REAL act (the password change).

## Honest open items
- **Cron redelivery** of dead letters: the Worker's `scheduled` entry is
  a deploy-shape decision (the owner's) — the records exist for it.
- **DNS-rebinding** is not defended (a public name resolving private);
  the literal-host guards + the Worker's egress are the current posture.
  Named, never silent.
- The console UI for subscriptions (the API + the delivery log are
  documented + tested; the Vue island's section is follow-up UX).
