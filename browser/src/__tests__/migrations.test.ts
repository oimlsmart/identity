// ─────────────────────────────────────────────────────────────────────
// The migration set's contract (TODO.restructure/15 wave 2 — identity's
// OWN set now), proven in-repo:
//
//   1. every migration applies cleanly, in filename order, to a fresh
//      database (the schema boots from the journal path alone);
//   2. the migrations' END STATE mirrors schema.sql (table and column
//      sets, so ALTER-carrying migrations prove themselves too) — the
//      drift tripwire that keeps the package's two DDL sources in
//      lockstep;
//   3. the naming rule holds: NNNN_name.sql, the filename-keyed
//      journal discipline (expand-only, never renumber — wrangler's
//      d1_migrations bookkeeping keys on the names, and the deployed
//      databases carry this set's history).
//
// The consumers' own suites pin the STORE against the same set (the
// smart monorepo's d1-store test, the identity service's memberships
// test, both reading MIGRATIONS_DIR).
// ─────────────────────────────────────────────────────────────────────

import { describe, it, expect } from 'vitest'
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { MIGRATIONS_DIR, SQLITE_SCHEMA_PATH } from '../../server/store/sqlite'

const FILES = readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort()

function shapeOf(db: Database.Database): Record<string, string[]> {
  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all() as Array<{ name: string }>
  const shape: Record<string, string[]> = {}
  for (const { name } of tables) {
    const cols = db.prepare(`PRAGMA table_info(${name})`).all() as Array<{ name: string }>
    shape[name] = cols.map(c => c.name).sort()
  }
  return shape
}

describe('the canonical migration set', () => {
  it('ships at least one migration and every name follows NNNN_name.sql', () => {
    expect(FILES.length).toBeGreaterThan(0)
    for (const f of FILES) {
      expect(f, `migration ${f} breaks the filename-keyed convention`).toMatch(/^\d{4}_[a-z0-9_]+\.sql$/)
    }
  })

  it('applies cleanly in filename order and the end state mirrors schema.sql', { timeout: 30_000 }, () => {
    // The 30 s budget (the 2026-08-31 evidence): the set is 21 migrations;
    // under the shared CI runner's load the default 5 s timed out on the
    // 0.1.7 release run (the apply + the shape mirror are honest work). The
    // budget follows the set's growth, never the reverse.
    const migrated = new Database(join(mkdtempSync(join(tmpdir(), 'oiml-ps-mig-')), 'm.db'))
    const fresh = new Database(join(mkdtempSync(join(tmpdir(), 'oiml-ps-schema-')), 's.db'))
    try {
      for (const f of FILES) migrated.exec(readFileSync(join(MIGRATIONS_DIR, f), 'utf-8'))
      fresh.exec(readFileSync(SQLITE_SCHEMA_PATH, 'utf-8'))
      expect(shapeOf(migrated)).toEqual(shapeOf(fresh))
    } finally {
      migrated.close()
      fresh.close()
    }
  })
})
