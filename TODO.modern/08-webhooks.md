# TODO.modern/08 — the outbound events (webhooks on the audit journal)

**Priority:** P2 · **Status:** DISPATCHABLE
RPs subscribe to account events (password_changed, mfa_enabled, session_revoked, pat_minted/revoked) — the journal already carries them.

## The acts
1. The subscription surface (session-gated): endpoint URL + the event set + the secret; the HMAC-signed delivery (the Stripe posture: the `Webhook-Signature` header, timestamped, replay-bounded).
2. The delivery: the journal's write path fans out best-effort (waitUntil on the Worker; the retry ladder with the honest dead-letter record — a failed delivery never blocks the act).
3. The events' shape: the audit event's envelope, documented in OpenAPI edition 2.
4. Specs: the signature verify (a consumer-side test), the retry, the dead letter; e2e: a subscriber's round-trip.

**Acceptance:** an RP receives a signed event for a subscribed act.
