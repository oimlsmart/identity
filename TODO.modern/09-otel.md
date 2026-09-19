# TODO.modern/09 — the observability depth (OTel + per-org analytics)

**Priority:** P2 · **Status:** IMPLEMENTED (the request-id seam) — the trace EXPORT is the honest open half

## What shipped
1. **X-Request-Id on every answer** (`browser/server/request-id.ts`, first in the
   app's middleware stack): generated (32 hex) or an inbound well-formed id
   honored — the safe alphabet `[A-Za-z0-9_.-]{8,64}`, anything else sanitized
   away (never echoed). Stamped BEFORE `next()`, so error answers carry it too.
2. **The typed store-outage answer names the id** (`request_id` in the 503 body)
   and the plain-500 log line is prefixed `[req <id>]` — a support conversation's
   reference resolves to the request. Specs: `src/__tests__/id-request-id.test.ts`
   (the REAL app factory + the REAL onError, with a real typed StoreUnavailable
   thrown inside the stack).
3. The Server-Timing instrument stays as-is (exact per-request wall time).

**Open (honest):** the trace EXPORT (the span tree app → store phase → statement,
OTLP HTTP relay vs Workers Analytics Engine) is an operator infrastructure
decision + a sized build — its own PR after the owner picks the destination. The
W3C `traceparent` inbound-honoring rides that same PR. Per-org analytics is the
dashboard's aggregation work over the journal (the rows exist).
Exact timing exists (Server-Timing); depth does not: no trace export, no per-request IDs in error answers, no tenant analytics.

## The acts
1. OTel: the Worker's trace export (Workers Analytics Engine or OTLP HTTP relay), the span tree (app → store phase → statement), the W3C traceparent honored inbound + emitted outbound (mail, siteverify, webhooks).
2. The request ID: every answer carries `X-Request-Id` (and error bodies name it) — support conversations reference it; it keys the trace.
3. Per-org analytics (the whitelabel tenants): sign-ins, exchanges, failures per org, on the dashboard's tenant view — the journal already carries the rows (the aggregation is the work).
4. The Server-Timing instrument stays (it is exact); OTel adds the correlation.

**Acceptance:** a support request with a request ID resolves to its trace; a tenant sees its own usage.
