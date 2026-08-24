// TODO.identity-ops/05 — the access-review report, unit-tested against
// a SEEDED local registry (the --db posture): the privileged holders are
// named, the findings fire, and the posture counts hold. The live path
// (--remote) is the same SQL through wrangler d1 execute.

import { describe, it, expect } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { queryLocalDb, buildAccessReviewReport } from '../../scripts/op-access-review'

function seedRegistry(): string {
  const dir = mkdtempSync(join(tmpdir(), 'op-access-review-'))
  const dbPath = join(dir, 'registry.db')
  const db = new Database(dbPath)
  db.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
      avatar_url TEXT, provider TEXT NOT NULL DEFAULT 'demo', provider_account_id TEXT,
      role TEXT NOT NULL DEFAULT 'user', roles TEXT, active INTEGER NOT NULL DEFAULT 1,
      org_id TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_login TEXT, email_verified_at TEXT
    );
    CREATE TABLE op_client_roles (
      user_id TEXT NOT NULL, client_id TEXT NOT NULL, roles TEXT NOT NULL,
      assigned_by TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT,
      PRIMARY KEY (user_id, client_id)
    );
    CREATE TABLE oidc_clients (
      client_id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT,
      redirect_uris TEXT NOT NULL, claims_policy TEXT, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), created_by TEXT
    );
    CREATE TABLE identity_providers (
      id TEXT PRIMARY KEY, kind TEXT NOT NULL, display_name TEXT NOT NULL,
      brand_mark TEXT, issuer TEXT, client_id TEXT NOT NULL, client_secret_ref TEXT,
      scopes TEXT, enabled INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), created_by TEXT, updated_at TEXT
    );
    CREATE TABLE oidc_keys (
      kid TEXT PRIMARY KEY, public_jwk TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), retired_at TEXT
    );
  `)
  const user = db.prepare('INSERT INTO users (id, email, name, role, roles, active, org_id, provider, last_login, email_verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
  user.run('u-admin', 'admin@example.org', 'The Administrator', 'admin', '["admin"]', 1, null, 'password', '2026-08-01 09:00:00', '2026-06-01 10:00:00')
  user.run('u-cs', 'cs@example.org', 'The Scheme Operator', 'cs_admin', '["cs_admin"]', 1, null, 'password', null, null)
  user.run('u-org', 'orgadmin@example.org', 'The Org Admin', 'org_admin', '["org_admin"]', 0, 'EX1', 'password', '2026-05-01 12:00:00', null)
  user.run('u-view', 'viewer@example.org', 'A Viewer', 'viewer', '["viewer"]', 1, null, 'demo', '2026-08-20 08:00:00', null)
  user.run('u-odd', 'odd@example.org', 'An Odd Account', 'superroot', '["superroot"]', 1, null, 'demo', null, null)
  db.prepare('INSERT INTO op_client_roles (user_id, client_id, roles) VALUES (?, ?, ?)').run('u-admin', 'oiml-smart-platform', '["admin"]')
  db.prepare('INSERT INTO op_client_roles (user_id, client_id, roles) VALUES (?, ?, ?)').run('u-view', 'oiml-smart-platform', '["viewer"]')
  const client = db.prepare('INSERT INTO oidc_clients (client_id, name, redirect_uris, status, created_by) VALUES (?, ?, ?, ?, ?)')
  client.run('oiml-smart-platform', 'The platform hub', '["https://platform.oimlsmart.org/auth/callback"]', 'active', 'admin@example.org')
  client.run('old-rp', 'A retired RP', '["https://old.example/cb"]', 'disabled', 'admin@example.org')
  const provider = db.prepare('INSERT INTO identity_providers (id, kind, display_name, issuer, client_id, enabled) VALUES (?, ?, ?, ?, ?, ?)')
  provider.run('github', 'github', 'GitHub', null, 'client-id', 1)
  provider.run('entra-old', 'oidc', 'Old Entra', 'https://login.microsoftonline.com/t/v2.0', 'client-id', 0)
  const key = db.prepare('INSERT INTO oidc_keys (kid, public_jwk, status, retired_at) VALUES (?, ?, ?, ?)')
  key.run('kid-current', '{}', 'active', null)
  key.run('kid-old', '{}', 'retired', '2026-07-01 00:00:00')
  db.close()
  return dbPath
}

describe('TODO.identity-ops/05 — the access-review report', () => {
  it('names the privileged holders, fires the findings, and holds the posture counts', () => {
    const dbPath = seedRegistry()
    try {
      const data = queryLocalDb(dbPath)
      const report = buildAccessReviewReport(data, 'the seeded test registry', new Date('2026-08-23T00:00:00Z'))

      // The privileged holders are named; the plain viewer is not.
      expect(report).toContain('admin@example.org')
      expect(report).toContain('cs@example.org')
      expect(report).toContain('orgadmin@example.org')
      expect(report).toContain('Privileged account holders (3)')
      expect(report).not.toMatch(/viewer@example\.org.*\|.*\|.*\|.*\|.*\|.*\|/) // not in the holders table

      // The per-client privileged assignment lands; the viewer's does not.
      expect(report).toContain('Per-client privileged assignments (1)')

      // The findings: the unknown role, the disabled privileged account,
      // the never-signed-in privileged account, the disabled client, the
      // disabled provider, the retired key trail.
      expect(report).toContain('odd@example.org` carries role(s) outside the platform vocabulary: superroot')
      expect(report).toContain('orgadmin@example.org` holds a privileged role while the account is DISABLED')
      expect(report).toContain('cs@example.org` (privileged) has never signed in')
      expect(report).toContain('RP client `old-rp` is disabled')
      expect(report).toContain('upstream provider `entra-old` is disabled')
      expect(report).toContain('1 retired signing key row(s)')

      // The posture counts.
      expect(report).toContain('accounts: 5 total, 4 active')
      expect(report).toContain('RP clients: 2 total (1 active)')
      expect(report).toContain('upstream providers: 2 total (1 enabled)')
      expect(report).toContain('signing keys: 2 in history (1 active in the JWKS)')

      // The header + the checklist.
      expect(report).toContain('Access review — OIML SMART identity service (2026 Q3)')
      expect(report).toContain('the seeded test registry')
      expect(report).toContain("The reviewer's checklist")
    } finally {
      rmSync(join(dbPath, '..'), { recursive: true, force: true })
    }
  })

  it('--redact masks the identifiers and keeps the signal (the public-repo CI posture)', () => {
    const dbPath = seedRegistry()
    try {
      const data = queryLocalDb(dbPath)
      const report = buildAccessReviewReport(data, 'the seeded test registry', new Date('2026-08-23T00:00:00Z'), { redact: true })

      // The identifiers are masked; the domains + roles + counts survive.
      expect(report).not.toContain('admin@example.org')
      expect(report).not.toContain('The Administrator')
      expect(report).toContain('a***@example.org')
      expect(report).toContain('REDACTED for the public job log')
      expect(report).toContain('Privileged account holders (3)')
      expect(report).toContain('accounts: 5 total, 4 active')
      // The findings fire against the masked identities.
      expect(report).toContain('o***@example.org` carries role(s) outside the platform vocabulary: superroot')
      expect(report).toContain('o***@example.org` holds a privileged role while the account is DISABLED')
    } finally {
      rmSync(join(dbPath, '..'), { recursive: true, force: true })
    }
  })
})
