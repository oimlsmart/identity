// ═══════════════════════════════════════════════════════════════════
// The i18n catalogs' compiler (2026-10-15): the AUTHORING format is
// YAML (src/i18n/en.yaml + fr.yaml — the translators' surface), the
// RUNTIME is the typed TS modules (src/i18n/en.ts + fr.ts — what every
// import consumes). The compiler reads the pair, enforces the EN/FR
// lockstep (the identical key sets, every value a non-empty string),
// and emits the modules byte-deterministically in the YAML's own key
// order.
//
//   npm run i18n:gen        — regenerate after editing the YAML
//
// The generated modules are COMMITTED (every consumer — vue-tsc, the
// gates, the mail compiler — reads them without a pre-step), and the
// drift test (src/__tests__/id-i18n-yaml.test.ts) fails any hand edit
// of the TS that the YAML does not back.
//
// NODE-ONLY (fs) — a scripts/ tool, never imported by server code.
// ═══════════════════════════════════════════════════════════════════
import { readFileSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'

const I18N_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'i18n')

export interface I18nGenerateResult {
  enTs: string
  frTs: string
  enKeys: number
  frKeys: number
  problems: string[]
}

/** Load one YAML catalog with the honest shape check. */
function loadCatalog(path: string): Record<string, string> {
  const raw = yaml.load(readFileSync(path, 'utf-8'))
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${path}: the catalog must be a YAML mapping of key → string`)
  }
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof key !== 'string' || key.trim() === '') throw new Error(`${path}: a key is empty or not a string`)
    if (typeof value !== 'string' || value.trim() === '') throw new Error(`${path}: '${key}' is empty or not a string`)
    out[key] = value
  }
  return out
}

/** The compiler's core: read the pair, enforce the lockstep, answer the
 *  two module texts. Pure given the files. */
export function generateI18n(): I18nGenerateResult {
  const en = loadCatalog(join(I18N_DIR, 'en.yaml'))
  const fr = loadCatalog(join(I18N_DIR, 'fr.yaml'))
  const problems: string[] = []
  const enKeys = Object.keys(en)
  const frKeys = Object.keys(fr)
  const frSet = new Set(frKeys)
  for (const key of enKeys) {
    if (!frSet.has(key)) problems.push(`fr.yaml is missing '${key}' (the EN/FR lockstep)`)
  }
  const enSet = new Set(enKeys)
  for (const key of frKeys) {
    if (!enSet.has(key)) problems.push(`fr.yaml carries '${key}', which en.yaml does not (the lockstep is the EN's key set)`)
  }
  if (problems.length) return { enTs: '', frTs: '', enKeys: enKeys.length, frKeys: frKeys.length, problems }

  const enTs = [
    '// ═══════════════════════════════════════════════════════════════════',
    '// GENERATED from src/i18n/en.yaml — the authoring surface is the YAML;',
    '// edit THAT and run `npm run i18n:gen`. Hand edits to this file are',
    '// overwritten (the drift test refuses them too). The MessageKey union',
    '// derives from this object: a missing key is a compile error at every',
    '// t() call site.',
    '// ═══════════════════════════════════════════════════════════════════',
    '',
    'export const en = {',
    ...enKeys.map(k => `  ${JSON.stringify(k)}: ${JSON.stringify(en[k])},`),
    '} as const',
    '',
    'export type MessageKey = keyof typeof en',
    '',
  ].join('\n')

  const frTs = [
    '// ═══════════════════════════════════════════════════════════════════',
    '// GENERATED from src/i18n/fr.yaml — the authoring surface is the YAML;',
    '// edit THAT and run `npm run i18n:gen`. The type binds fr to the EN',
    '// key set: the two never drift.',
    '// ═══════════════════════════════════════════════════════════════════',
    '',
    "import type { MessageKey } from './en'",
    '',
    'export const fr: Record<MessageKey, string> = {',
    ...frKeys.map(k => `  ${JSON.stringify(k)}: ${JSON.stringify(fr[k])},`),
    '}',
    '',
  ].join('\n')

  return { enTs, frTs, enKeys: enKeys.length, frKeys: frKeys.length, problems }
}

function main(): void {
  const { enTs, frTs, enKeys, frKeys, problems } = generateI18n()
  if (problems.length) {
    for (const problem of problems) console.error(`✗ ${problem}`)
    process.exit(1)
  }
  writeFileSync(join(I18N_DIR, 'en.ts'), enTs)
  writeFileSync(join(I18N_DIR, 'fr.ts'), frTs)
  console.log(`✓ i18n: ${enKeys} EN keys, ${frKeys} FR keys — en.ts + fr.ts regenerated from the YAML pair`)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main()
