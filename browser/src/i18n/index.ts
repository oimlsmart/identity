// ═══════════════════════════════════════════════════════════════════
// The i18n layer, identity-service shape: the mini-catalog of the
// account.* + mail.* namespaces (./en.ts, ./fr.ts — extracted from the
// smart monorepo at the wave-02 move, EN/FR lockstep-typed). In-house
// on purpose, the same posture as the monorepo's layer this descends
// from.
//
//   t(key, params?)   — resolve a catalog key in the current locale,
//                       English fallback, the key itself as last resort
//                       (+ a dev-mode console warning, once per key).
//   useLocale()       — { locale, locales, setLocale } for components.
//   setLocaleUser()   — scope the persisted preference to the signed-in
//                       account; signed-out browsing uses the unscoped
//                       key.
// ═══════════════════════════════════════════════════════════════════
import { ref, watch } from 'vue'
import { en, type MessageKey } from './en'
import { fr } from './fr'

export type { MessageKey } from './en'

export type Locale = 'en' | 'fr'
export const LOCALES: readonly Locale[] = ['en', 'fr']
export const DEFAULT_LOCALE: Locale = 'en'

const catalogs: Record<Locale, Record<string, string>> = { en, fr }

const STORAGE_PREFIX = 'oiml-smart-locale'

/** The account the preference belongs to (the signed-in user's email),
 *  or null for signed-out browsing. */
let storageUser: string | null = null

function storageKey(): string {
  return storageUser ? `${STORAGE_PREFIX}:${storageUser}` : STORAGE_PREFIX
}

function readStored(): Locale {
  try {
    if (typeof localStorage !== 'undefined') {
      const stored = localStorage.getItem(storageKey())
      if (stored === 'en' || stored === 'fr') return stored
    }
  } catch { /* storage unavailable — private mode, SSR, tests */ }
  return DEFAULT_LOCALE
}

const locale = ref<Locale>(readStored())

function persist(code: Locale): void {
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(storageKey(), code)
  } catch { /* storage unavailable */ }
}

watch(locale, persist, { immediate: true })

/** Re-scope the persisted preference to `email` (null = signed out) and
 *  reload it. */
export function setLocaleUser(email: string | null): void {
  const next = email ?? null
  if (next === storageUser) return
  storageUser = next
  locale.value = readStored()
}

/** The current locale — for non-component callers that cannot take the
 *  composable's ref. */
export function currentLocale(): Locale {
  return locale.value
}

/** Keys already warned about — the dev-mode log fires once per key. */
const warnedKeys = new Set<string>()

function interpolate(message: string, params?: Record<string, string | number>): string {
  if (!params) return message
  return message.replace(/\{(\w+)\}/g, (match, name: string) =>
    params[name] !== undefined ? String(params[name]) : match)
}

function warnOnce(kind: string, key: string): void {
  if (!import.meta.env?.DEV) return
  const stamp = `${kind}:${key}`
  if (warnedKeys.has(stamp)) return
  warnedKeys.add(stamp)
  console.warn(`[i18n] ${kind}: ${key}`)
}

/** Resolve a catalog key. French wins when active; a key missing there
 *  falls back to English (dev-logged); a key missing from every catalog
 *  renders the key itself (dev-logged) — never a blank string. */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const table = catalogs[locale.value] ?? catalogs[DEFAULT_LOCALE]
  let message = table[key]
  if (message === undefined && locale.value !== DEFAULT_LOCALE) {
    warnOnce('missing locale key, English fallback', `${locale.value}:${key}`)
    message = catalogs[DEFAULT_LOCALE][key]
  }
  if (message === undefined) {
    warnOnce('missing catalog key', key)
    message = key
  }
  return interpolate(message, params)
}

export function useLocale() {
  function setLocale(code: Locale) {
    if (!LOCALES.includes(code) || code === locale.value) return
    locale.value = code
    persist(code)
  }
  return { locale, locales: LOCALES, setLocale }
}
