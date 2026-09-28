// ═══════════════════════════════════════════════════════════════════
// The member-domains registry sync: copy the pipeline's built
// dist/domains.json into the vendored artifact this service bundles
// (src/generated/domains.json). The member-domains repo is the source
// of truth; THIS repo consumes only the built artifact (never the YAML
// or the CSV). CI never runs this — the committed copy is the
// deployable artifact; re-run + commit when the pipeline ships a new
// generated_at.
//
//   npx tsx scripts/sync-member-domains.ts [--source <path-to-dist>]
// ═══════════════════════════════════════════════════════════════════

import { copyFileSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const home = process.env.HOME ?? ''
const defaultSource = join(home, 'src', 'oimlsmart', 'member-domains', 'dist', 'domains.json')
const sourceIdx = process.argv.indexOf('--source')
const source = sourceIdx >= 0 ? process.argv[sourceIdx + 1]! : defaultSource
const dest = join(import.meta.dirname ?? '.', '..', 'src', 'generated', 'domains.json')

const parsed = JSON.parse(readFileSync(source, 'utf-8')) as { version?: number; generated_at?: string }
if (parsed.version !== 2) {
  console.error(`the artifact is not version 2 (got ${JSON.stringify(parsed.version)}) — refresh the member-domains pipeline first`)
  process.exit(1)
}
if (!parsed.generated_at) {
  console.error('the artifact carries no generated_at — refuse (the audit trail needs the vintage)')
  process.exit(1)
}
copyFileSync(source, dest)
console.log(`synced ${source} → ${dest} (version 2, generated_at ${parsed.generated_at})`)
