# TODO.modern/09 — the observability depth (OTel + per-org analytics)

**Priority:** P2 · **Status:** IMPLEMENTED (the request-id seam + the trace-context/export core) — per-org analytics is the honest open half

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
3. **The trace-context seam** (`browser/server/obs/trace.ts`, #follow-up PR):
   W3C `traceparent` HONORED inbound (validated 00-trace-span-flags form; garbage
   never echoes — a fresh root answers) and ECHOED on every answer with a fresh
   child span id; **the OTLP/HTTP JSON export** — one span per request
   (`METHOD /path`, status, sub-ms duration via performance.now, `app.request_id`
   carrying the request-id seam's id, `service.name` from `OTEL_SERVICE_NAME`
   default `oiml-identity`), fire-and-forget (waitUntil on the Worker, the
   swallowed honest catch on node — a collector's failure is never the answer's
   failure). **The arm: `OTEL_EXPORTER_OTLP_ENDPOINT` — unset = the whole
   feature OFF, byte-identical answers (the Turnstile pattern).** Specs:
   `src/__tests__/id-otel.test.ts` (7).
4. The Server-Timing instrument stays as-is (exact per-request wall time).

**Open (honest):** the deeper span TREE (store phase → statement children) —
the store-phase timing exists (Server-Timing); riding it as span children is
follow-up once a collector sees real use. OUTBOUND traceparent on third-party
fetches (mail/siteverify/webhooks) — the correlation core (inbound + echo +
export) is in; outbound propagation to providers that ignore it is marginal.
Per-org analytics is the dashboard's aggregation work over the journal (the
rows exist) — its own PR with the scaling gate's full attention.
**Acceptance state:** a support request with a request ID resolves to its trace ✓
(a collector at the endpoint is the owner's ops act); a tenant sees its own
usage — open.
