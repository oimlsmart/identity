// ═══════════════════════════════════════════════════════════════════
// The pushed authorization requests' SQLite rows (TODO.modern/11,
// RFC 9126) — the known-devices pattern: free functions over the
// shared handle. The D1 store implements the same surface in
// server/store/d1.ts; the schema arrives via schema.sql +
// 0031_pushed_authorization_requests.sql (the lockstep the
// migrations test pins).
// ═══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'
import type { PushedAuthorizationRequest } from '../../store'

interface ParRow {
  uri: string
  client_id: string
  params: string
  expires_at: string
}

function toPar(row: ParRow): PushedAuthorizationRequest {
  return { uri: row.uri, clientId: row.client_id, params: row.params, expiresAt: row.expires_at }
}

export function createPushedAuthorizationRequest(
  db: Database.Database,
  input: { uri: string; clientId: string; params: string; expiresAt: string },
): void {
  db.prepare(
    'INSERT INTO pushed_authorization_requests (uri, client_id, params, expires_at) VALUES (?, ?, ?, ?)',
  ).run(input.uri, input.clientId, input.params, input.expiresAt)
  // The expired rows ride out opportunistically (a tiny table; the
  // insert is the natural sweeper — never a request-path read).
  db.prepare("DELETE FROM pushed_authorization_requests WHERE julianday(expires_at) <= julianday('now')").run()
}

export function consumePushedAuthorizationRequest(
  db: Database.Database,
  uri: string,
): PushedAuthorizationRequest | null {
  const consume = db.prepare(
    `UPDATE pushed_authorization_requests
       SET consumed = 1
     WHERE uri = ? AND consumed = 0
       AND julianday(expires_at) > julianday('now')`,
  ).run(uri)
  if (consume.changes === 0) return null
  const row = db.prepare('SELECT * FROM pushed_authorization_requests WHERE uri = ?').get(uri) as ParRow | undefined
  return row ? toPar(row) : null
}
