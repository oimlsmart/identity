// ═══════════════════════════════════════════════════════════════════
// The notification subscriptions store (TODO.notify/02) — the SQLite
// (better-sqlite3, node-only) sync implementation, the events.ts
// pattern. Three tables:
//
//   notify_rules         the per-user rule rows (subscribe|mute on a
//                        key pattern, the pattern SPLIT into its pinned
//                        legs so the reverse match — every user's rules
//                        covering one event — resolves in SQL);
//   notify_entity_mutes  the thread-level mutes (the bell's Muted
//                        state, the email footer's unsubscribe);
//   notify_preferences   one row per user: the per-category email
//                        posture (immediate / digest / off).
//
// Plus TODO.notify/03's inbox state: notify_inbox_state, the per-user
// per-event read/done markers the computed feed joins (one row per
// (user, event), written lazily at the first act on the row).
//
// Plus TODO.notify/04's delivery store: notify_deliveries, one row per
// (event, recipient) — the email channel's per-recipient record (the
// reason, the resolved posture, the email leg's state; the digest
// sweep's queue and the retry sweep's read).
//
// The D1 store (../d1.ts) runs the SAME statements against the binding;
// the d1-store suite's tripwire pins the two schemas in lockstep.
// ═══════════════════════════════════════════════════════════════════

import { getDb } from './store'
import type {
  NotifyDelivery,
  NotifyEntityMute,
  NotifyInboxState,
  NotifyPreferences,
  NotifyRule,
} from '../../store'

interface RuleRow {
  id: string
  user_id: string
  pattern: string
  domain: string
  entity_id: string | null
  action: string | null
  mode: string
  channel_overrides: string | null
  created_at: string
}

function toNotifyRule(row: RuleRow): NotifyRule {
  return {
    id: row.id,
    userId: row.user_id,
    pattern: row.pattern,
    domain: row.domain,
    entityId: row.entity_id,
    action: row.action,
    mode: row.mode as NotifyRule['mode'],
    channelOverrides: row.channel_overrides,
    createdAt: row.created_at,
  }
}

export function listNotifyRules(userId: string): NotifyRule[] {
  const rows = getDb()
    .prepare('SELECT * FROM notify_rules WHERE user_id = ? ORDER BY created_at, id')
    .all(userId) as RuleRow[]
  return rows.map(toNotifyRule)
}

export function putNotifyRule(input: {
  id: string
  userId: string
  pattern: string
  domain: string
  entityId: string | null
  action: string | null
  mode: NotifyRule['mode']
  channelOverrides: string | null
}): NotifyRule {
  const db = getDb()
  db.prepare(
    `INSERT INTO notify_rules (id, user_id, pattern, domain, entity_id, action, mode, channel_overrides)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (user_id, pattern) DO UPDATE SET
       domain = excluded.domain,
       entity_id = excluded.entity_id,
       action = excluded.action,
       mode = excluded.mode,
       channel_overrides = excluded.channel_overrides`,
  ).run(input.id, input.userId, input.pattern, input.domain, input.entityId, input.action, input.mode, input.channelOverrides)
  return toNotifyRule(
    db.prepare('SELECT * FROM notify_rules WHERE user_id = ? AND pattern = ?').get(input.userId, input.pattern) as RuleRow,
  )
}

export function deleteNotifyRule(userId: string, pattern: string): boolean {
  const res = getDb()
    .prepare('DELETE FROM notify_rules WHERE user_id = ? AND pattern = ?')
    .run(userId, pattern)
  return res.changes > 0
}

/** The resolution's reverse match: a rule covers the event when its
 *  pinned legs equal the event's columns (NULL = the wild leg). */
export function notifyRulesForEvent(filter: { domain: string; entityId: string; action: string }): NotifyRule[] {
  const rows = getDb()
    .prepare(
      `SELECT * FROM notify_rules
       WHERE domain = ? AND (entity_id IS NULL OR entity_id = ?) AND (action IS NULL OR action = ?)
       ORDER BY created_at, id`,
    )
    .all(filter.domain, filter.entityId, filter.action) as RuleRow[]
  return rows.map(toNotifyRule)
}

interface EntityMuteRow {
  id: string
  user_id: string
  domain: string
  entity_id: string
  created_at: string
}

function toNotifyEntityMute(row: EntityMuteRow): NotifyEntityMute {
  return {
    id: row.id,
    userId: row.user_id,
    domain: row.domain,
    entityId: row.entity_id,
    createdAt: row.created_at,
  }
}

export function listNotifyEntityMutes(userId: string): NotifyEntityMute[] {
  const rows = getDb()
    .prepare('SELECT * FROM notify_entity_mutes WHERE user_id = ? ORDER BY created_at, id')
    .all(userId) as EntityMuteRow[]
  return rows.map(toNotifyEntityMute)
}

export function putNotifyEntityMute(input: {
  id: string
  userId: string
  domain: string
  entityId: string
}): NotifyEntityMute {
  const db = getDb()
  db.prepare(
    `INSERT INTO notify_entity_mutes (id, user_id, domain, entity_id) VALUES (?, ?, ?, ?)
     ON CONFLICT (user_id, domain, entity_id) DO NOTHING`,
  ).run(input.id, input.userId, input.domain, input.entityId)
  return toNotifyEntityMute(
    db.prepare(
      'SELECT * FROM notify_entity_mutes WHERE user_id = ? AND domain = ? AND entity_id = ?',
    ).get(input.userId, input.domain, input.entityId) as EntityMuteRow,
  )
}

export function deleteNotifyEntityMute(userId: string, domain: string, entityId: string): boolean {
  const res = getDb()
    .prepare('DELETE FROM notify_entity_mutes WHERE user_id = ? AND domain = ? AND entity_id = ?')
    .run(userId, domain, entityId)
  return res.changes > 0
}

export function notifyEntityMutesForEvent(domain: string, entityId: string): NotifyEntityMute[] {
  const rows = getDb()
    .prepare('SELECT * FROM notify_entity_mutes WHERE domain = ? AND entity_id = ? ORDER BY created_at, id')
    .all(domain, entityId) as EntityMuteRow[]
  return rows.map(toNotifyEntityMute)
}

interface PreferencesRow {
  user_id: string
  channels: string
  updated_at: string
}

function toNotifyPreferences(row: PreferencesRow): NotifyPreferences {
  return { userId: row.user_id, channels: row.channels, updatedAt: row.updated_at }
}

export function getNotifyPreferences(userId: string): NotifyPreferences | null {
  const row = getDb()
    .prepare('SELECT * FROM notify_preferences WHERE user_id = ?')
    .get(userId) as PreferencesRow | undefined
  return row ? toNotifyPreferences(row) : null
}

export function putNotifyPreferences(userId: string, channels: string): NotifyPreferences {
  const db = getDb()
  db.prepare(
    `INSERT INTO notify_preferences (user_id, channels) VALUES (?, ?)
     ON CONFLICT (user_id) DO UPDATE SET channels = excluded.channels, updated_at = datetime('now')`,
  ).run(userId, channels)
  return toNotifyPreferences(
    db.prepare('SELECT * FROM notify_preferences WHERE user_id = ?').get(userId) as PreferencesRow,
  )
}

// ── the inbox state (TODO.notify/03) ─────────────────────────────────

interface InboxStateRow {
  user_id: string
  event_id: string
  read_at: string | null
  done_at: string | null
  saved_at: string | null
  created_at: string
}

function toNotifyInboxState(row: InboxStateRow): NotifyInboxState {
  return {
    userId: row.user_id,
    eventId: row.event_id,
    readAt: row.read_at,
    doneAt: row.done_at,
    savedAt: row.saved_at,
    createdAt: row.created_at,
  }
}

export function listNotifyInboxStates(userId: string): NotifyInboxState[] {
  const rows = getDb()
    .prepare('SELECT * FROM notify_inbox_state WHERE user_id = ? ORDER BY created_at, event_id')
    .all(userId) as InboxStateRow[]
  return rows.map(toNotifyInboxState)
}

/** The marker write: each PRESENT flag stamps (datetime('now')) or
 *  clears (NULL) its column; absent flags keep. The row lands on the
 *  first act (INSERT with both columns defaulted), later acts UPDATE. */
export function putNotifyInboxState(input: {
  userId: string
  eventId: string
  read?: boolean
  done?: boolean
  saved?: boolean
}): NotifyInboxState {
  const db = getDb()
  db.prepare(
    'INSERT OR IGNORE INTO notify_inbox_state (user_id, event_id) VALUES (?, ?)',
  ).run(input.userId, input.eventId)
  if (input.read !== undefined) {
    db.prepare("UPDATE notify_inbox_state SET read_at = CASE WHEN ? THEN datetime('now') ELSE NULL END WHERE user_id = ? AND event_id = ?")
      .run(input.read ? 1 : 0, input.userId, input.eventId)
  }
  if (input.done !== undefined) {
    db.prepare("UPDATE notify_inbox_state SET done_at = CASE WHEN ? THEN datetime('now') ELSE NULL END WHERE user_id = ? AND event_id = ?")
      .run(input.done ? 1 : 0, input.userId, input.eventId)
  }
  if (input.saved !== undefined) {
    db.prepare("UPDATE notify_inbox_state SET saved_at = CASE WHEN ? THEN datetime('now') ELSE NULL END WHERE user_id = ? AND event_id = ?")
      .run(input.saved ? 1 : 0, input.userId, input.eventId)
  }
  return toNotifyInboxState(
    db.prepare('SELECT * FROM notify_inbox_state WHERE user_id = ? AND event_id = ?')
      .get(input.userId, input.eventId) as InboxStateRow,
  )
}

// ── the email channel's delivery store (TODO.notify/04) ──────────────

interface DeliveryRow {
  id: string
  event_id: string
  user_id: string
  reason: string
  email: string
  email_status: string | null
  email_at: string | null
  created_at: string
}

function toNotifyDelivery(row: DeliveryRow): NotifyDelivery {
  return {
    id: row.id,
    eventId: row.event_id,
    userId: row.user_id,
    reason: row.reason,
    email: row.email as NotifyDelivery['email'],
    emailStatus: row.email_status as NotifyDelivery['emailStatus'],
    emailAt: row.email_at,
    createdAt: row.created_at,
  }
}

/** The fan-out's write: the upsert on UNIQUE (event_id, user_id). The
 *  status only ever moves FORWARD through the caller's marks — the
 *  upsert itself never overwrites a terminal stamp (a re-driven event
 *  refreshes reason + posture, keeps the email leg's state). An INITIAL
 *  write carrying a terminal status stamps email_at (pending states —
 *  NULL and 'digest_pending' — never carry a stamp). */
export function putNotifyDelivery(input: {
  id: string
  eventId: string
  userId: string
  reason: string
  email: NotifyDelivery['email']
  emailStatus: NotifyDelivery['emailStatus']
}): NotifyDelivery {
  const db = getDb()
  db.prepare(
    `INSERT INTO notify_deliveries (id, event_id, user_id, reason, email, email_status, email_at)
     VALUES (?, ?, ?, ?, ?, ?, CASE WHEN ? IS NULL OR ? = 'digest_pending' THEN NULL ELSE datetime('now') END)
     ON CONFLICT (event_id, user_id) DO UPDATE SET
       reason = excluded.reason,
       email = excluded.email`,
  ).run(input.id, input.eventId, input.userId, input.reason, input.email, input.emailStatus, input.emailStatus, input.emailStatus)
  return toNotifyDelivery(
    db.prepare('SELECT * FROM notify_deliveries WHERE event_id = ? AND user_id = ?')
      .get(input.eventId, input.userId) as DeliveryRow,
  )
}

export function getNotifyDelivery(eventId: string, userId: string): NotifyDelivery | null {
  const row = getDb()
    .prepare('SELECT * FROM notify_deliveries WHERE event_id = ? AND user_id = ?')
    .get(eventId, userId) as DeliveryRow | undefined
  return row ? toNotifyDelivery(row) : null
}

export function listNotifyDeliveriesForEvent(eventId: string): NotifyDelivery[] {
  const rows = getDb()
    .prepare('SELECT * FROM notify_deliveries WHERE event_id = ? ORDER BY created_at, id')
    .all(eventId) as DeliveryRow[]
  return rows.map(toNotifyDelivery)
}

/** The digest sweep's first read: the DISTINCT users holding pending
 *  rows (one digest message per user per run). */
export function notifyDigestPendingUsers(): string[] {
  const rows = getDb()
    .prepare("SELECT DISTINCT user_id FROM notify_deliveries WHERE email_status = 'digest_pending' ORDER BY user_id")
    .all() as Array<{ user_id: string }>
  return rows.map(r => r.user_id)
}

export function notifyDigestPendingForUser(userId: string): NotifyDelivery[] {
  const rows = getDb()
    .prepare("SELECT * FROM notify_deliveries WHERE user_id = ? AND email_status = 'digest_pending' ORDER BY created_at, id")
    .all(userId) as DeliveryRow[]
  return rows.map(toNotifyDelivery)
}

/** The retry sweep's read: the failed immediates, oldest first. */
export function notifyFailedDeliveries(limit = 100): NotifyDelivery[] {
  const rows = getDb()
    .prepare("SELECT * FROM notify_deliveries WHERE email_status = 'failed' ORDER BY created_at, id LIMIT ?")
    .all(limit) as DeliveryRow[]
  return rows.map(toNotifyDelivery)
}

/** The status mark. The terminal marks stamp email_at; a re-queue to
 *  'digest_pending' CLEARS it (a pending row carries no stamp). */
export function markNotifyDelivery(id: string, status: NonNullable<NotifyDelivery['emailStatus']>): void {
  const terminal = status === 'digest_pending' ? null : "datetime('now')"
  getDb()
    .prepare(`UPDATE notify_deliveries SET email_status = ?, email_at = ${terminal ?? 'NULL'} WHERE id = ?`)
    .run(status, id)
}
