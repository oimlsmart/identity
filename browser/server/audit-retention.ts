// ═══════════════════════════════════════════════════════════════════
// The audit journal's retention policy — ONE resolution every surface
// shares (TODO.restructure/27 item 4; TODO.restructure/28 workstream A):
// the dashboard's retention statement (routes/op-dashboard.ts) and the
// ops purge (scripts/op-audit-retention.ts, the identity-operations
// nightly) both resolve the same env var the same way.
//
//   AUDIT_RETENTION_DAYS   the journal's retention window, in days.
//                          Events strictly older than the window are
//                          purged by the ops run. UNSET (or empty) =
//                          the NO-PURGE posture: the journal is
//                          retained for the life of the registry,
//                          byte-identical to the pre-2026-09 behavior.
//                          The number is the OWNER's decision — a
//                          Worker var (the dashboard's statement) and a
//                          GitHub repository variable (the ops run);
//                          this code never supplies a default N.
//
// WORKER-SAFE: no node built-ins.
// ═══════════════════════════════════════════════════════════════════

type EnvLike = Record<string, string | undefined>

/** Resolve AUDIT_RETENTION_DAYS: null = the var is unset (the no-purge
 *  default); a whole number >= 1 = the retention window in days. A
 *  SET-but-malformed value throws — a purge window is a destructive
 *  policy, so a typo is a loud refusal, never a guess or a silent
 *  fallback to no-purge. */
export function parseAuditRetentionDays(value: string | undefined): number | null {
  if (value === undefined || value === null) return null
  const trimmed = value.trim()
  if (!trimmed) return null
  if (!/^\d+$/.test(trimmed) || Number(trimmed) < 1) {
    throw new Error(
      `AUDIT_RETENTION_DAYS is set to '${value}' but is not a whole number of days >= 1 — fix the variable; the journal keeps everything until it parses`,
    )
  }
  return Number(trimmed)
}

/** The purge cutoff: events with a timestamp strictly older than this
 *  ISO instant are purgeable (an event exactly at the cutoff is KEPT —
 *  the window is "older than N days", never "N days or older"). The
 *  journal's timestamps are new Date().toISOString() values (UTC,
 *  millisecond precision), so the ISO strings compare lexicographically
 *  exactly as their instants do — the same compare the dashboard's
 *  from/to filters and the remote SQL leg rely on. */
export function auditCutoffIso(now: Date, retentionDays: number): string {
  return new Date(now.getTime() - retentionDays * 86_400_000).toISOString()
}

/** The dashboard answers' retention statement (op-dashboard's six
 *  surfaces emit it verbatim; the ops runbook states the same rule).
 *  UNSET answers the no-purge text byte-identically to the
 *  pre-2026-09 statement — the default posture is unchanged, so the
 *  statement stays honest without the var. */
export function auditRetentionStatement(env: EnvLike): string {
  const days = parseAuditRetentionDays(env.AUDIT_RETENTION_DAYS)
  const journal = days === null
    ? 'The audit journal is retained for the life of the registry (no automated purge). '
    : `The audit journal is purged of events older than ${days} days (AUDIT_RETENTION_DAYS=${days}; the nightly identity-operations run). `
  return journal
    + 'The heartbeat history is retained by GitHub Actions under its own policy. '
    + 'The dashboard computes its counters at request time and stores nothing.'
}
