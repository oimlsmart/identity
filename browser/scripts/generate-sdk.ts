// TODO.modern/07 — the SDK generation step: dump the LIVE spec (the
// drift-gated OPENAPI_SPEC) as JSON for the generator, run
// @hey-api/openapi-ts, remove the intermediate. The generated output
// (sdk/gen) is a committed build artifact — `npm run sdk:check` proves
// it fresh (regenerate → git diff must be empty). NODE-ONLY (a build
// script; never imported by server code).
import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const browserRoot = join(here, '..')
const tmp = join(browserRoot, 'sdk', 'openapi.tmp.json')

async function main() {
  const { OPENAPI_SPEC } = await import(join(browserRoot, 'server', 'openapi', 'spec.ts'))
  mkdirSync(join(browserRoot, 'sdk'), { recursive: true })
  writeFileSync(tmp, JSON.stringify(OPENAPI_SPEC, null, 2))
  try {
    const run = spawnSync('npx', ['openapi-ts'], { cwd: browserRoot, stdio: 'inherit' })
    if (run.status !== 0) process.exit(run.status ?? 1)
  } finally {
    rmSync(tmp, { force: true })
  }
}

main()
