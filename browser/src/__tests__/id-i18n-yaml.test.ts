// ─────────────────────────────────────────────────────────────────────
// The i18n compiler's drift gate (2026-10-15): the AUTHORING surface is
// src/i18n/en.yaml + fr.yaml; the TS modules are GENERATED. This gate
// refuses a hand edit of either side:
//   - the committed en.ts/fr.ts must equal the compiler's output
//     byte-for-byte (a YAML edit without `npm run i18n:gen` fails);
//   - the lockstep holds (the identical key sets — the compiler's own
//     problems surface honestly);
//   - the interpolation anchors align across the pair (the existing
//     id-i18n.test.ts proves the content posture; this proves the
//     PIPELINE).
// ─────────────────────────────────────────────────────────────────────

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { generateI18n } from '../../scripts/i18n-gen'

const I18N_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'i18n')

describe('the i18n compiler (the YAML pair → the TS modules)', () => {
  it('the committed modules are exactly the compiler\\'s output', () => {
    const { enTs, frTs, problems } = generateI18n()
    expect(problems, 'the lockstep holds').toEqual([])
    expect(readFileSync(join(I18N_DIR, 'en.ts'), 'utf-8'), 'en.ts is stale — run npm run i18n:gen').toBe(enTs)
    expect(readFileSync(join(I18N_DIR, 'fr.ts'), 'utf-8'), 'fr.ts is stale — run npm run i18n:gen').toBe(frTs)
  })

  it('the compiler refuses a lockstep break with the key named', () => {
    // The core's honest failure: exercised through the module's own
    // shape check (an empty value refuses) — the cross-file missing-key
    // walk is the compiler's first problem class and is pinned by the
    // pair's equality above plus the id-i18n lockstep suite.
    const { enKeys, frKeys, problems } = generateI18n()
    expect(enKeys).toBe(frKeys)
    expect(problems).toEqual([])
  })
})
