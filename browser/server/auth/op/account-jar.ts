// ═══════════════════════════════════════════════════════════════════
// The account jar — the browser's multi-account awareness (the account
// chooser wave): alongside the active `oiml-session` cookie, a second
// browser-scoped cookie (`oiml-accounts`) remembers up to five recent
// accounts { sessionId, userId, email, displayName, orgId }. Every
// sign-in refreshes an entry (LRU, one per ACCOUNT — a fresh session
// for a known account replaces its row); every session-ending act
// drops its own entry; the chooser page and the console's "sign out of
// all accounts" consume it.
//
// THE TRUST POSTURE — httpOnly + server-verified, never signed-and-
// trusted: the cookie's display fields are conveniences, never
// decisions. Every read re-verifies each entry against the LIVE
// session rows (a chosen swap requires a live session row whose
// account matches the entry's userId, and the display fields re-
// project from that row); a dead row falls back to the login page with
// the remembered email prefilled. A hand-forged jar can therefore at
// most name sessions the writer already holds — possession of the
// session token IS the credential, exactly as for the active cookie —
// and every authorization decision re-reads the store.
//
// WORKER-SAFE: hono's cookie/adapter helpers + WebCrypto-adjacent
// primitives only (TextEncoder/btoa), no node built-ins. The public
// signatures take the structural KernelContext — never hono's own
// Context — the session seam's discipline (../session.ts).
// ═══════════════════════════════════════════════════════════════════

import type { Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { getStore, type AuthUserPayload } from '../../store'
import { SESSION_COOKIE, sessionCookieOpts, type KernelContext } from '../../session'

export type { KernelContext } from '../../session'

export const ACCOUNTS_COOKIE = 'oiml-accounts'

/** The jar's capacity: five recent accounts, most recent first (the
 *  Google chooser's own posture). */
export const ACCOUNT_JAR_CAPACITY = 5

/** One remembered account. `sessionId` is the session TOKEN (the value
 *  the active cookie would carry — the store's deleteSession key and
 *  the swap's new cookie value); the display fields are the sign-in
 *  moment's projection, refreshed from the live row whenever one
 *  exists. */
export interface AccountJarEntry {
  sessionId: string
  userId: string
  email: string
  displayName: string
  orgId: string | null
}

/** One resolved jar entry: the stored row plus its liveness verdict.
 *  A LIVE entry's display fields come from the session payload (the
 *  store's truth — the account may have been renamed since the
 *  sign-in); a DEAD entry keeps the jar's remembered fields (the login
 *  prefill's raw material). */
export interface ResolvedJarEntry {
  entry: AccountJarEntry
  live: boolean
  user: AuthUserPayload | null
}

// ── field caps (a hand-forged or corrupt cookie never becomes a
//    multi-kilobyte cookie or an unbounded render) ────────────────────
const CAP_SESSION = 256
const CAP_ID = 128
const CAP_EMAIL = 254
const CAP_NAME = 128

function capped(value: unknown, cap: number): string {
  return typeof value === 'string' ? value.slice(0, cap) : ''
}

function sanitizeEntry(raw: unknown): AccountJarEntry | null {
  if (!raw || typeof raw !== 'object') return null
  const rec = raw as Record<string, unknown>
  const entry: AccountJarEntry = {
    sessionId: capped(rec.sessionId, CAP_SESSION),
    userId: capped(rec.userId, CAP_ID),
    email: capped(rec.email, CAP_EMAIL),
    displayName: capped(rec.displayName, CAP_NAME),
    orgId: typeof rec.orgId === 'string' && rec.orgId ? capped(rec.orgId, CAP_ID) : null,
  }
  // The two identity fields are the entry's spine — without them the
  // entry addresses nothing (the display fields may be empty).
  if (!entry.sessionId || !entry.userId) return null
  return entry
}

// ── the cookie's wire format: UTF-8-safe base64url JSON ──────────────
// Display names are human names (any script); encodeURIComponent would
// triple every non-Latin byte, so the JSON rides base64url of the
// UTF-8 bytes (TextEncoder + btoa — both runtimes ship them).

/** The cookie's wire format encoder (exported for the codec's tests —
 *  the readers go through decodeJar). */
export function encodeJar(entries: AccountJarEntry[]): string {
  const bytes = new TextEncoder().encode(JSON.stringify(entries))
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The jar as the request presents it, decoded (exported for the
 *  codec's tests; tolerant — garbage reads as no jar). */
export function decodeJar(value: string | undefined): AccountJarEntry[] {
  if (!value) return []
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/')
  let json: string
  try {
    json = new TextDecoder().decode(Uint8Array.from(atob(b64), ch => ch.charCodeAt(0)))
  } catch {
    return [] // a corrupt cookie reads as no jar — never an error page
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    return []
  }
  if (!Array.isArray(parsed)) return []
  const entries: AccountJarEntry[] = []
  for (const raw of parsed) {
    const entry = sanitizeEntry(raw)
    if (entry) entries.push(entry)
  }
  return entries
}

// ── the pure halves (the unit tests' target) ─────────────────────────

/** The jar after a sign-in: the account's fresh entry first, any prior
 *  entry for the SAME account (by userId) or the SAME session gone,
 *  the capacity enforced from the tail. Pure. */
export function addJarEntry(entries: AccountJarEntry[], fresh: AccountJarEntry): AccountJarEntry[] {
  const kept = entries.filter(e => e.userId !== fresh.userId && e.sessionId !== fresh.sessionId)
  return [fresh, ...kept].slice(0, ACCOUNT_JAR_CAPACITY)
}

/** The jar after a session-ending act: the entry naming that session
 *  is gone. Pure. */
export function removeJarSession(entries: AccountJarEntry[], sessionToken: string): AccountJarEntry[] {
  return entries.filter(e => e.sessionId !== sessionToken)
}

/** The jar entry an account's fresh session projects. */
export function jarEntryFor(token: string, user: AuthUserPayload): AccountJarEntry {
  return {
    sessionId: token,
    userId: user.id,
    email: user.email,
    displayName: user.name,
    orgId: user.orgId ?? null,
  }
}

// ── the cookie posture ───────────────────────────────────────────────

/** The jar outlives any single session (a dead entry is the login
 *  prefill's raw material, not a credential), so the window is long —
 *  half a year — while staying a deliberate, bounded retention. */
export function accountsCookieOpts(c: KernelContext) {
  return {
    ...sessionCookieOpts(c),
    maxAge: 180 * 24 * 60 * 60,
  }
}

/** The jar as the request presents it (tolerant — garbage reads as no
 *  jar). */
export function readAccountJar(c: KernelContext): AccountJarEntry[] {
  return decodeJar(getCookie(c as Context, ACCOUNTS_COOKIE))
}

function writeAccountJar(c: KernelContext, entries: AccountJarEntry[]): void {
  setCookie(c as Context, ACCOUNTS_COOKIE, encodeJar(entries), accountsCookieOpts(c))
}

/** A sign-in's jar refresh: add/refresh the account's entry (LRU) and
 *  re-issue the cookie. */
export function touchAccountJar(c: KernelContext, token: string, user: AuthUserPayload): void {
  writeAccountJar(c, addJarEntry(readAccountJar(c), jarEntryFor(token, user)))
}

/** A session-ending act's jar drop: the entry naming the ended session
 *  goes; the cookie is only re-issued when something actually left. */
export function dropAccountJarSession(c: KernelContext, sessionToken: string): void {
  const current = readAccountJar(c)
  const next = removeJarSession(current, sessionToken)
  if (next.length !== current.length) writeAccountJar(c, next)
}

/** The whole jar clears (the sign-out-of-all act). */
export function clearAccountJar(c: KernelContext): void {
  deleteCookie(c as Context, ACCOUNTS_COOKIE, { path: '/' })
}

/** Every entry re-judged against the LIVE session rows, jar order kept
 *  (most recent first). Bounded by the capacity — at most five reads,
 *  never a per-row loop over an unbounded set. */
export async function resolveAccountJar(c: KernelContext): Promise<ResolvedJarEntry[]> {
  const store = getStore()
  const resolved: ResolvedJarEntry[] = []
  for (const entry of readAccountJar(c)) {
    const user = await store.getSessionUser(entry.sessionId)
    resolved.push({ entry, live: !!user, user })
  }
  return resolved
}

// ── the continue-target + login-fallback URL helpers ─────────────────

/** The chooser's continue target: a same-origin RELATIVE path, or
 *  nothing. The normalization round-trips through a fixed origin so a
 *  protocol-relative (`//host`), a backslash, or an absolute URL can
 *  never smuggle the navigation off-host. */
export function sanitizeContinueTarget(raw: string | undefined | null): string | null {
  const value = raw?.trim() ?? ''
  if (!value || value.length > 2048) return null
  try {
    const url = new URL(value, 'http://op.local')
    if (url.origin !== 'http://op.local') return null
    return `${url.pathname}${url.search}${url.hash}`
  } catch {
    return null
  }
}

/** The honest fallback when a chosen account has no live session: the
 *  instance's login page, the flow's re-entry target in its
 *  `redirect` seat, the remembered email prefilled when the jar knows
 *  one. */
export function loginUrlForContinue(continueTarget: string | null, email?: string | null): string {
  const url = new URL('/', 'http://op.local')
  url.searchParams.set('redirect', continueTarget ?? '/op/account')
  if (email) url.searchParams.set('email', email)
  return `${url.pathname}${url.search}`
}

// ── the chooser's two decision helpers (the routes' shared reads) ────

/** The live session a chosen userId addresses, or null (unknown user,
 *  dead row, or a row belonging to a DIFFERENT account than the entry
 *  claims — the forged-cookie collapse). Answers the entry (the swap's
 *  new cookie value) and the verified payload (the jar refresh's
 *  projection). */
export async function liveJarEntryForUser(
  c: KernelContext,
  userId: string,
): Promise<{ entry: AccountJarEntry; payload: AuthUserPayload } | null> {
  for (const resolved of await resolveAccountJar(c)) {
    if (resolved.live && resolved.user && resolved.entry.userId === userId && resolved.user.id === userId) {
      return { entry: resolved.entry, payload: resolved.user }
    }
  }
  return null
}

/** The active session cookie's value + its live payload (the chooser
 *  context's "current" badge; the swap's old-row awareness). */
export async function activeJarContext(c: KernelContext): Promise<{ token: string; user: AuthUserPayload } | null> {
  const token = getCookie(c as Context, SESSION_COOKIE)
  if (!token) return null
  const user = await getStore().getSessionUser(token)
  return user ? { token, user } : null
}
