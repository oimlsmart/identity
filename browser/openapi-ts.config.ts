import { defineConfig } from '@hey-api/openapi-ts'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// TODO.modern/07 — the SDK generation config. The input is written by
// scripts/generate-sdk.ts (the live OPENAPI_SPEC dumped as JSON); the
// output is sdk/gen — a committed BUILD ARTIFACT, never hand-edited,
// freshness-gated by `npm run sdk:check` (regenerate → diff must be
// empty). The absolute file URL: hey-api treats bare paths as its
// registry shorthand.
const here = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  input: `file://${join(here, 'sdk', 'openapi.tmp.json')}`,
  output: {
    path: join(here, 'sdk', 'gen'),
  },
  plugins: ['@hey-api/client-fetch', '@hey-api/typescript', '@hey-api/sdk'],
})
