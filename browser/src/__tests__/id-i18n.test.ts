// ─────────────────────────────────────────────────────────────────────
// The i18n layer (src/i18n/index.ts), proven in-process: the EN/FR
// lockstep (the type enforces the shape; this proves the CONTENT
// posture — no empty entries, the interpolation anchors aligned), the
// locale resolution + fallback, and the persistence scoping (the
// per-account key where signed in, the unscoped key where anonymous —
// the AccountChip wires the scope; the ISO-benchmark quick win,
// smart's TODO.identity-features/11 item 3).
//
// The module is singleton state (the locale ref is module-level), so
// the suite runs against the REAL module with a stubbed localStorage;
// each test restores the scope + locale it moved.
// ─────────────────────────────────────────────────────────────────────

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { en } from '../i18n/en'
import { fr } from '../i18n/fr'
import { currentLocale, setLocaleUser, t, useLocale } from '../i18n'

/** The minimal Storage stand-in (the layer reads/writes two keys). */
function stubLocalStorage(): Map<string, string> {
  const map = new Map<string, string>()
  const storage = {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => { map.set(k, String(v)) },
    removeItem: (k: string) => { map.delete(k) },
    clear: () => map.clear(),
    key: (i: number) => [...map.keys()][i] ?? null,
    get length() { return map.size },
  } satisfies Storage
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true })
  return map
}

describe('the EN/FR catalogs (the lockstep pair)', () => {
  it('every key resolves to a non-empty string in both languages', () => {
    const enKeys = Object.keys(en)
    const frKeys = Object.keys(fr)
    expect(frKeys.sort()).toEqual(enKeys.sort())
    for (const key of enKeys) {
      expect(en[key as keyof typeof en].trim(), `en:${key} is empty`).not.toBe('')
      expect(fr[key as keyof typeof fr].trim(), `fr:${key} is empty`).not.toBe('')
    }
  })

  it('the {placeholders} align across the pair (a French sentence never drops an interpolation anchor)', () => {
    const anchors = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort()
    for (const key of Object.keys(en) as Array<keyof typeof en>) {
      expect(anchors(fr[key]), `fr:${key} placeholders`).toEqual(anchors(en[key]))
    }
  })
})

describe('the locale layer', () => {
  let store: Map<string, string>

  beforeEach(() => {
    store = stubLocalStorage()
    setLocaleUser(null)
    useLocale().setLocale('en')
  })

  afterEach(() => {
    setLocaleUser(null)
    useLocale().setLocale('en')
    Object.defineProperty(globalThis, 'localStorage', { value: undefined, configurable: true })
  })

  it('t() resolves the active locale, interpolates, and falls back to the key', () => {
    expect(t('login.submit')).toBe('Sign in')
    useLocale().setLocale('fr')
    expect(t('login.submit')).toBe('Se connecter')
    expect(t('login.heading', { product: 'OIML SMART Identity' })).toBe('Connexion à OIML SMART Identity')
    // @ts-expect-error an unknown key renders itself, never a blank string
    expect(t('no.such.key')).toBe('no.such.key')
  })

  it('the choice persists under the anonymous key where signed out', () => {
    useLocale().setLocale('fr')
    expect(store.get('oiml-smart-locale')).toBe('fr')
    expect(store.get('oiml-smart-locale:ada@example.org')).toBeUndefined()
  })

  it('the signed-in account carries its own key (setLocaleUser scopes + reloads)', () => {
    useLocale().setLocale('fr') // the anonymous choice
    setLocaleUser('ada@example.org')
    // A fresh scope with no stored preference reads the default…
    expect(currentLocale()).toBe('en')
    useLocale().setLocale('fr')
    expect(store.get('oiml-smart-locale:ada@example.org')).toBe('fr')
    // …and signing out returns to the anonymous choice.
    setLocaleUser(null)
    expect(currentLocale()).toBe('fr')
  })

  it('the stored preference wins on scope entry (the account\'s choice survives sign-out)', () => {
    setLocaleUser('ada@example.org')
    useLocale().setLocale('fr')
    setLocaleUser(null)
    useLocale().setLocale('en') // the anonymous browsing moved on
    setLocaleUser('ada@example.org')
    expect(currentLocale()).toBe('fr') // the account's own choice, restored
  })
})
