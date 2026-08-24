// ─────────────────────────────────────────────────────────────────────
// op-access-review.ts — the quarterly access review's answer
// (TODO.identity-ops/05; the operating plan is docs/deployment/
// identity-operations.md, PR #175): "who holds OP admin and privileged
// roles RIGHT NOW", answered from the identity service's live registry
// (or a seeded one, for the test posture), printed as the review
// artifact.
//
// The privileged set on the OP (grounded in the code's own gates):
//   - admin / cs_admin  — the OP's admin surfaces (the client registry,
//     the provider registry, account administration; routes/op.ts,
//     routes/op-upstream.ts, routes/op-accounts.ts all gate on these);
//   - org_admin         — delegated organization administration
//     (TODO.identity/10, /op/admin/users).
// The report also flags accounts carrying a role OUTSIDE the platform
// vocabulary (@oimlsmart/platform-server/vocab's APP_ROLES) — a finding, always.
//
// Sources:
//   --remote (default)  the live D1: drives `wrangler d1 execute
//                       oiml-smart-platform-identity --remote --json`
//                       (the operator's / CI's Cloudflare credentials;
//                       the D1 name overridable with --d1);
//   --db <path>         a local SQLite file (a seeded dev registry —
//                       the test + rehearsal posture).
//
// Output: markdown on stdout, and ONLY stdout — the workflow
// (identity-access-review.yml) prints it into the job log and never
// uploads an artifact. THE PUBLIC-REPO DISCIPLINE: this repository is
// public, so a workflow job log is a PUBLIC surface — the workflow runs
// the report with --redact (emails and names masked; the counts, the
// roles, and the findings' shapes carry the review). The full named
// report is the operator-local command (the same --remote SQL, run with
// the operator's Cloudflare credentials, never in CI):
//
// Usage (from browser/):
//   npx tsx scripts/op-access-review.ts --remote
//   npx tsx scripts/op-access-review.ts --remote --redact   (the CI posture)
//   npx tsx scripts/op-access-review.ts --db .cache/id-01/identity.db
// ─────────────────────────────────────────────────────────────────────

import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import Database from 'better-sqlite3'
import { APP_ROLES } from '@oimlsmart/platform-server/vocab'

/** The roles whose holders the review names (the OP's gates above). */
const PRIVILEGED_ROLES = ['admin', 'cs_admin', 'org_admin'] as const

const DEFAULT_D1 = 'oiml-smart-platform-identity'

// ── the query layer (one SQL dialect: D1 and the node store are both
//    SQLite) ─────────────────────────────────────────────────────────

export interface AccessReviewData {
  users: Array<{
    id: string; email: string; name: string; role: string; roles: string | null
    org_id: string | null; active: number; provider: string
    last_login: string | null; created_at: string; email_verified_at: string | null
  }>
  clientRoles: Array<{ user_id: string; client_id: string; roles: string }>
  clients: Array<{ client_id: string; name: string; status: string; created_at: string; created_by: string | null }>
  providers: Array<{ id: string; kind: string; display_name: string; enabled: number; issuer: string | null; created_at: string }>
  keys: Array<{ kid: string; status: string; created_at: string; retired_at: string | null }>
}

const QUERIES: Record<keyof AccessReviewData, string> = {
  users: 'SELECT id, email, name, role, roles, org_id, active, provider, last_login, created_at, email_verified_at FROM users ORDER BY email',
  clientRoles: 'SELECT user_id, client_id, roles FROM op_client_roles ORDER BY user_id, client_id',
  clients: 'SELECT client_id, name, status, created_at, created_by FROM oidc_clients ORDER BY client_id',
  providers: 'SELECT id, kind, display_name, enabled, issuer, created_at FROM identity_providers ORDER BY id',
  keys: 'SELECT kid, status, created_at, retired_at FROM oidc_keys ORDER BY created_at',
}

/** Query a local SQLite file (better-sqlite3, the repo's own driver). */
export function queryLocalDb(dbPath: string): AccessReviewData {
  const db = new Database(dbPath, { readonly: true })
  try {
    const out = {} as Record<keyof AccessReviewData, unknown>
    for (const [key, sql] of Object.entries(QUERIES) as Array<[keyof AccessReviewData, string]>) {
      out[key] = db.prepare(sql).all()
    }
    return out as AccessReviewData
  } finally {
    db.close()
  }
}

/** Query the live D1 through wrangler (the secret-free read path; the
 *  operator's CLOUDFLARE_* credentials ride the environment). */
export function queryRemoteD1(d1Name: string): AccessReviewData {
  const out = {} as Record<keyof AccessReviewData, unknown>
  for (const [key, sql] of Object.entries(QUERIES) as Array<[keyof AccessReviewData, string]>) {
    const run = spawnSync('npx', ['wrangler', 'd1', 'execute', d1Name, '--remote', '--json', '--command', sql], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    })
    if (run.status !== 0) {
      throw new Error(`wrangler d1 execute (${key}) failed: ${(run.stderr || run.stdout || '').slice(0, 400)}`)
    }
    // wrangler --json answers an array of per-database results.
    const parsed = JSON.parse(run.stdout) as Array<{ results?: unknown[] }>
    out[key] = parsed[0]?.results ?? []
  }
  return out as AccessReviewData
}

// ── the report (pure over the query results) ─────────────────────────

function roleSet(row: { role: string; roles: string | null }): string[] {
  let parsed: string[] = []
  try { parsed = row.roles ? (JSON.parse(row.roles) as string[]) : [] } catch { parsed = [] }
  return parsed.length ? parsed : [row.role]
}

function fmt(value: string | null): string {
  return value && value.trim() ? value : '(none)'
}

// ── the redaction (the public-repo CI posture) ───────────────────────
// The masked shape keeps the review's signal (the counts, the roles,
// the org domains, the findings) and drops the identifiers: an email
// keeps its first letter + domain (`v***@example.org`); a name keeps
// each word's initial (`Ms. Vera Fullarc` → `M. V. F.`).
function maskEmail(email: string): string {
  const at = email.lastIndexOf('@')
  if (at <= 0) return '***'
  return `${email[0]}***@${email.slice(at + 1)}`
}

function maskName(name: string): string {
  return name.split(/\s+/).filter(Boolean).map(w => `${w[0]}.`).join(' ') || '(masked)'
}

export function buildAccessReviewReport(data: AccessReviewData, source: string, now = new Date(), opts?: { redact?: boolean }): string {
  const redact = opts?.redact === true
  const showEmail = (email: string): string => redact ? maskEmail(email) : email
  const showName = (name: string): string => redact ? maskName(name) : name
  const lines: string[] = []
  const quarter = `${now.getUTCFullYear()} Q${Math.floor(now.getUTCMonth() / 3) + 1}`
  lines.push(`# Access review — OIML SMART identity service (${quarter})`)
  lines.push('')
  lines.push(`Generated ${now.toISOString()} from ${source}.`)
  if (redact) {
    lines.push('')
    lines.push('REDACTED for the public job log: account identifiers are masked (`v***@example.org`, initials for names). The named report is the operator-local run (never CI).')
  }
  lines.push('')
  lines.push('The privileged set on the OP: `admin`, `cs_admin` (the OP admin surfaces: the client registry, the provider registry, account administration), `org_admin` (delegated organization administration). Every holder is named below; an empty table is the honest answer, never an omission.')
  lines.push('')

  // ── 1. the privileged account holders ──
  const privileged = data.users
    .map(u => ({ ...u, effectiveRoles: roleSet(u) }))
    .filter(u => u.effectiveRoles.some(r => (PRIVILEGED_ROLES as readonly string[]).includes(r)))
  lines.push(`## Privileged account holders (${privileged.length})`)
  lines.push('')
  if (privileged.length) {
    lines.push('| Email | Name | Roles | Org | Active | Last login | Email verified |')
    lines.push('|---|---|---|---|---|---|---|')
    for (const u of privileged) {
      lines.push(`| ${showEmail(u.email)} | ${showName(u.name)} | ${u.effectiveRoles.join(', ')} | ${fmt(u.org_id)} | ${u.active ? 'yes' : 'NO'} | ${fmt(u.last_login)} | ${fmt(u.email_verified_at)} |`)
    }
  } else {
    lines.push('(none)')
  }
  lines.push('')

  // ── 2. the per-client privileged assignments ──
  const byId = new Map(data.users.map(u => [u.id, u]))
  const clientPriv = data.clientRoles
    .map(cr => ({ ...cr, parsed: (() => { try { return JSON.parse(cr.roles) as string[] } catch { return [] } })() }))
    .filter(cr => cr.parsed.some(r => (PRIVILEGED_ROLES as readonly string[]).includes(r)))
  lines.push(`## Per-client privileged assignments (${clientPriv.length})`)
  lines.push('')
  lines.push('The OP-side per-client role assignments (op_client_roles) that carry a privileged role on a specific relying party:')
  lines.push('')
  if (clientPriv.length) {
    lines.push('| Account | Client | Roles on that client |')
    lines.push('|---|---|---|')
    for (const cr of clientPriv) {
      lines.push(`| ${showEmail(byId.get(cr.user_id)?.email ?? cr.user_id)} | ${cr.client_id} | ${cr.parsed.join(', ')} |`)
    }
  } else {
    lines.push('(none)')
  }
  lines.push('')

  // ── 3. findings (the review's attention list) ──
  const findings: string[] = []
  const knownRoles = new Set<string>(APP_ROLES)
  for (const u of data.users) {
    const unknown = roleSet(u).filter(r => !knownRoles.has(r))
    if (unknown.length) findings.push(`\`${showEmail(u.email)}\` carries role(s) outside the platform vocabulary: ${unknown.join(', ')}`)
  }
  for (const u of privileged) {
    if (!u.active) findings.push(`\`${showEmail(u.email)}\` holds a privileged role while the account is DISABLED (the row stays for the audit trail; confirm the disable is intended)`)
    if (!u.last_login) findings.push(`\`${showEmail(u.email)}\` (privileged) has never signed in`)
  }
  for (const c of data.clients.filter(c => c.status !== 'active')) {
    findings.push(`RP client \`${c.client_id}\` is ${c.status} (kept for the audit trail; confirm it stays disabled)`)
  }
  for (const p of data.providers.filter(p => !p.enabled)) {
    findings.push(`upstream provider \`${p.id}\` is disabled (its links stay; confirm it should)`)
  }
  const retiredKeys = data.keys.filter(k => k.status === 'retired')
  if (retiredKeys.length) findings.push(`${retiredKeys.length} retired signing key row(s) remain in the history (expected: the rotation ceremony's trail)`)
  lines.push(`## Findings (${findings.length})`)
  lines.push('')
  if (findings.length) {
    for (const f of findings) lines.push(`- ${f}`)
  } else {
    lines.push('(none)')
  }
  lines.push('')

  // ── 4. the registry posture (counts) ──
  lines.push('## Registry posture')
  lines.push('')
  lines.push(`- accounts: ${data.users.length} total, ${data.users.filter(u => u.active).length} active`)
  lines.push(`- RP clients: ${data.clients.length} total (${data.clients.filter(c => c.status === 'active').length} active)`)
  lines.push(`- upstream providers: ${data.providers.length} total (${data.providers.filter(p => p.enabled).length} enabled)`)
  lines.push(`- signing keys: ${data.keys.length} in history (${data.keys.filter(k => k.status === 'active').length} active in the JWKS)`)
  lines.push('')

  // ── 5. the reviewer's checklist ──
  lines.push('## The reviewer\'s checklist')
  lines.push('')
  lines.push('- Every named holder above is a CURRENT, intended holder (offboarded staff hold nothing).')
  lines.push('- Every finding above is dispositioned (kept with a note, or remediated).')
  lines.push('- The per-client privileged assignments match each relying party\'s documented need (least privilege).')
  lines.push('- This artifact is filed with the quarter\'s review record (internal; never a public artifact).')
  return lines.join('\n') + '\n'
}

// ── the CLI ──────────────────────────────────────────────────────────

function main(): void {
  const args = process.argv.slice(2)
  const flag = (name: string): string | undefined => {
    const i = args.indexOf(`--${name}`)
    return i >= 0 ? args[i + 1] : undefined
  }
  const dbPath = flag('db')
  const d1Name = flag('d1') ?? DEFAULT_D1
  const remote = args.includes('--remote') || !dbPath
  const redact = args.includes('--redact')

  let data: AccessReviewData
  let source: string
  if (remote) {
    data = queryRemoteD1(d1Name)
    source = `the live D1 \`${d1Name}\` (wrangler --remote)`
  } else {
    data = queryLocalDb(dbPath!)
    source = `the local registry \`${dbPath}\``
  }
  process.stdout.write(buildAccessReviewReport(data, source, new Date(), { redact }))
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  try {
    main()
  } catch (e) {
    console.error(`op-access-review failed: ${e instanceof Error ? e.message : String(e)}`)
    process.exit(1)
  }
}
