# TODO.modern/09 — the observability depth (OTel + per-org analytics)

**Priority:** P2 · **Status:** DISPATCHABLE
Exact timing exists (Server-Timing); depth does not: no trace export, no per-request IDs in error answers, no tenant analytics.

## The acts
1. OTel: the Worker's trace export (Workers Analytics Engine or OTLP HTTP relay), the span tree (app → store phase → statement), the W3C traceparent honored inbound + emitted outbound (mail, siteverify, webhooks).
2. The request ID: every answer carries `X-Request-Id` (and error bodies name it) — support conversations reference it; it keys the trace.
3. Per-org analytics (the whitelabel tenants): sign-ins, exchanges, failures per org, on the dashboard's tenant view — the journal already carries the rows (the aggregation is the work).
4. The Server-Timing instrument stays (it is exact); OTel adds the correlation.

**Acceptance:** a support request with a request ID resolves to its trace; a tenant sees its own usage.
