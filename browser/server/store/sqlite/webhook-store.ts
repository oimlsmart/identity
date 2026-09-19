// ═══════════════════════════════════════════════════════════════════
// The outbound webhooks' SQLite rows (TODO.modern/08) — the pat-store
// pattern: free functions over the shared Database handle, rows mapped
// to the seam's types. The D1 store implements the same surface in
// server/store/d1.ts; the schema arrives via schema.sql's CREATE IF
// NOT EXISTS (and the D1 migration set carries the identical end
// state — 0029_webhooks.sql, the lockstep the migrations test pins).
// ═══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'
import type { WebhookDeliveryRecord, WebhookSubscription } from '../../store'

interface SubscriptionRow {
  id: string
  account_id: string
  url: string
  events: string
  secret: string
  active: number
  created_at: string
}

interface DeliveryRow {
  id: string
  subscription_id: string
  account_id: string
  event: string
  url: string
  attempts: number
  last_status: number
  delivered: number
  body_digest: string
  recorded_at: string
}

/** The defensive events-cell parse: a malformed cell reads as the
 *  empty set, never trusted (the parseOrgContacts posture). */
function parseEvents(json: string): string[] {
  try {
    const parsed = JSON.parse(json) as unknown
    return Array.isArray(parsed) ? parsed.filter((e): e is string => typeof e === 'string') : []
  } catch {
    return []
  }
}

function toSubscription(row: SubscriptionRow): WebhookSubscription {
  return {
    id: row.id,
    accountId: row.account_id,
    url: row.url,
    events: parseEvents(row.events),
    secret: row.secret,
    active: row.active === 1,
    createdAt: row.created_at,
  }
}

function toDelivery(row: DeliveryRow): WebhookDeliveryRecord {
  return {
    id: row.id,
    subscriptionId: row.subscription_id,
    accountId: row.account_id,
    event: row.event,
    url: row.url,
    attempts: row.attempts,
    lastStatus: row.last_status,
    delivered: row.delivered === 1,
    bodyDigest: row.body_digest,
    recordedAt: row.recorded_at,
  }
}

export function createWebhookSubscription(
  db: Database.Database,
  input: { id: string; accountId: string; url: string; events: string[]; secret: string },
): WebhookSubscription {
  db.prepare(
    `INSERT INTO webhook_subscriptions (id, account_id, url, events, secret)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(input.id, input.accountId, input.url, JSON.stringify(input.events), input.secret)
  return getWebhookSubscription(db, input.id)!
}

export function getWebhookSubscription(db: Database.Database, id: string): WebhookSubscription | null {
  const row = db.prepare('SELECT * FROM webhook_subscriptions WHERE id = ?').get(id) as SubscriptionRow | undefined
  return row ? toSubscription(row) : null
}

export function listWebhookSubscriptions(db: Database.Database, accountId: string): WebhookSubscription[] {
  const rows = db.prepare(
    'SELECT * FROM webhook_subscriptions WHERE account_id = ? ORDER BY created_at, rowid',
  ).all(accountId) as SubscriptionRow[]
  return rows.map(toSubscription)
}

export function revokeWebhookSubscription(db: Database.Database, id: string, accountId: string): boolean {
  const res = db.prepare(
    'UPDATE webhook_subscriptions SET active = 0 WHERE id = ? AND account_id = ?',
  ).run(id, accountId)
  return res.changes > 0
}

export function recordWebhookDelivery(
  db: Database.Database,
  input: Omit<WebhookDeliveryRecord, 'id'> & { id?: string },
): void {
  db.prepare(
    `INSERT INTO webhook_deliveries
       (id, subscription_id, account_id, event, url, attempts, last_status, delivered, body_digest)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    input.id ?? crypto.randomUUID(),
    input.subscriptionId,
    input.accountId,
    input.event,
    input.url,
    input.attempts,
    input.lastStatus,
    input.delivered ? 1 : 0,
    input.bodyDigest,
  )
}

export function listWebhookDeliveries(db: Database.Database, accountId: string, limit = 50): WebhookDeliveryRecord[] {
  const rows = db.prepare(
    'SELECT * FROM webhook_deliveries WHERE account_id = ? ORDER BY recorded_at DESC, rowid DESC LIMIT ?',
  ).all(accountId, limit) as DeliveryRow[]
  return rows.map(toDelivery)
}
