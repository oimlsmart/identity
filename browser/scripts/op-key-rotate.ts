// ─────────────────────────────────────────────────────────────────────
// op-key-rotate.ts — the OP signing-key rotation ceremony
// (TODO.identity-ops/02; the operating plan is docs/deployment/
// identity-operations.md, PR #175; the runbook section is
// docs/deployment/identity-deploy.md → "Key rotation").
//
// The OP signs ID tokens with one ES256 pair per deployment; the private
// half rides the OP_SIGNING_KEY Worker secret (never the repo, never the
// database, never the logs), the public half registers in oidc_keys on
// first use, and JWKS serves every ACTIVE row so a rotation never
// strands an in-flight token. This script IS the ceremony:
//
//   rotate   1. fetch the incumbent JWKS (the overlap baseline),
//            2. generate the successor ES256 pair (the kid derived the
//               OP's own way — server/auth/op/keys.ts's kidFor),
//            3. WITHOUT --apply: print the private JWK ONCE plus the
//               exact `wrangler secret put` instruction (the script
//               never touches the secret store by default);
//               WITH --apply: pipe the private JWK to `wrangler secret
//               put OP_SIGNING_KEY --env <env>` over stdin itself (never
//               argv, never a file, never the log),
//            4. poll the JWKS until it advertises BOTH the incumbent
//               kids AND the new kid (the overlap assert — the poll
//               itself triggers the new key's first-use registration),
//            5. print the retirement note: the old row retires by the
//               documented admin act after the longest token lifetime
//               plus margin (the verify command included);
//
//   verify   assert a JWKS advertises every --expect-kids entry (the
//            standalone overlap check, and the post-retirement check
//            with the retired kid absent via --absent-kids);
//
//   retirement-note   print the retirement admin act for a kid (the SQL
//            + the retire-after rule), without rotating anything.
//
// Usage (from browser/):
//   npx tsx scripts/op-key-rotate.ts rotate --env identity [--apply] [--url https://id.oimlsmart.org]
//   npx tsx scripts/op-key-rotate.ts verify --url https://id.oimlsmart.org --expect-kids <old>,<new>
//   npx tsx scripts/op-key-rotate.ts retirement-note --env identity --kid <old>
//
// The private key material appears EXACTLY ONCE: on the ceremony
// terminal's stdout (the manual path) or inside the stdin pipe to
// wrangler (the --apply path). It is never written to disk by the
// script and never echoed to a log.
// ─────────────────────────────────────────────────────────────────────

import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { kidFor } from '../server/auth/op/keys'

/** The deployments the ceremony knows (env name → the public base URL). */
const DEPLOYMENTS: Record<string, string> = {
  identity: 'https://id.oimlsmart.org',
  'identity-preview': 'https://id-preview.oimlsmart.org',
}

/** The retirement margin: the access-token TTL and the RP-side JWKS
 *  cache are both one hour (OP_ACCESS_TOKEN_TTL_MS in
 *  server/auth/op/config.ts, JWKS_TTL_MS in @oimlsmart/platform-server/oidc), so 24
 *  hours is the calm default; a compromise passes --retire-after-hours 0. */
const DEFAULT_RETIRE_AFTER_HOURS = 24

export interface SuccessorPair {
  /** The private JWK JSON (the OP_SIGNING_KEY material), kid stamped. */
  privateJwkJson: string
  /** The public half (kid/alg/use stamped, the JWKS row's shape). */
  publicJwk: JsonWebKey & { kid: string; alg: string; use: string }
  kid: string
}

/** Generate the successor ES256 pair. WebCrypto only (the same primitive
 *  the OP's dev-key path uses). */
export async function generateSuccessorPair(): Promise<SuccessorPair> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const publicJwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } as JsonWebKey
  const kid = await kidFor(publicJwk)
  const privateJwkJson = JSON.stringify({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, d: priv.d, kid })
  return { privateJwkJson, publicJwk: { ...publicJwk, kid, alg: 'ES256', use: 'sig' }, kid }
}

/** The kids a JWKS document currently advertises. */
export async function fetchJwksKids(baseUrl: string, fetchImpl: typeof fetch = fetch): Promise<string[]> {
  const base = baseUrl.replace(/\/+$/, '')
  const res = await fetchImpl(`${base}/jwks.json`)
  if (!res.ok) throw new Error(`the JWKS at ${base}/jwks.json answered HTTP ${res.status}`)
  const jwks = await res.json() as { keys?: Array<{ kid?: string }> }
  return (jwks.keys ?? []).map(k => k.kid ?? '')
}

/** The overlap assert: poll until the JWKS advertises EVERY expected kid
 *  (and, when given, no longer advertises the absent ones). Answers the
 *  missing/lingering kids on success ([]), throws on timeout. */
export async function pollJwksKids(
  baseUrl: string,
  opts: { expectKids?: string[]; absentKids?: string[]; timeoutMs?: number; intervalMs?: number; fetchImpl?: typeof fetch },
): Promise<{ advertised: string[]; missing: string[]; lingering: string[] }> {
  const expectKids = opts.expectKids ?? []
  const absentKids = opts.absentKids ?? []
  const timeoutMs = opts.timeoutMs ?? 300_000
  const intervalMs = opts.intervalMs ?? 5_000
  const fetchImpl = opts.fetchImpl ?? fetch
  const deadline = Date.now() + timeoutMs
  let advertised: string[] = []
  let missing = expectKids
  let lingering: string[] = []
  while (Date.now() < deadline) {
    advertised = await fetchJwksKids(baseUrl, fetchImpl)
    missing = expectKids.filter(k => !advertised.includes(k))
    lingering = absentKids.filter(k => advertised.includes(k))
    if (missing.length === 0 && lingering.length === 0) return { advertised, missing, lingering }
    await new Promise(r => setTimeout(r, intervalMs))
  }
  throw new Error(
    `the JWKS at ${baseUrl} did not reach the expected state within ${Math.round(timeoutMs / 1000)}s — ` +
    `missing: ${missing.join(', ') || 'none'}; still advertised: ${lingering.join(', ') || 'none'}; advertised: ${advertised.join(', ') || 'none'}`,
  )
}

/** The retirement note (the admin act is an operator's SQL, never this
 *  script's): the exact command + the retire-after rule. */
export function buildRetirementNote(opts: { env: string; kid: string; retireAfterHours: number; url: string }): string {
  const retireAt = new Date(Date.now() + opts.retireAfterHours * 60 * 60 * 1000).toISOString()
  const db = `oiml-smart-platform-${opts.env}`
  return [
    `── the retirement note ──────────────────────────────────────────────`,
    `The old key's row stays ACTIVE through the overlap: JWKS serves every`,
    `active row, so in-flight ID tokens keep validating. The longest token`,
    `lifetime is one hour and the RP-side JWKS cache is one hour; the old`,
    `row retires NO EARLIER than ${retireAt} (${opts.retireAfterHours}h margin)`,
    `by the admin act (a deliberate SQL statement, the operator's hand):`,
    ``,
    `  npx wrangler d1 execute ${db} --remote \\`,
    `    --command "UPDATE oidc_keys SET status='retired', retired_at=datetime('now') WHERE kid='${opts.kid}'"`,
    ``,
    `Then prove the row left the JWKS answer:`,
    ``,
    `  npx tsx scripts/op-key-rotate.ts verify --url ${opts.url} --absent-kids ${opts.kid}`,
    ``,
    `On COMPROMISE there is no margin: retire the row at once; in-flight`,
    `tokens die at the RPs' next JWKS fetch (the one-hour cache TTL).`,
  ].join('\n')
}

/** The --apply act: pipe the private JWK to `wrangler secret put` over
 *  stdin. The material never appears in argv, a file, or the log. */
export function applySigningKeySecret(env: string, privateJwkJson: string): void {
  const run = spawnSync('npx', ['wrangler', 'secret', 'put', 'OP_SIGNING_KEY', '--env', env], {
    input: privateJwkJson,
    stdio: ['pipe', 'inherit', 'inherit'],
  })
  if (run.status !== 0) {
    throw new Error(`wrangler secret put OP_SIGNING_KEY --env ${env} exited ${run.status} — the secret store is untouched unless it answered success`)
  }
}

// ── the CLI ──────────────────────────────────────────────────────────

function flagValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`)
  return i >= 0 ? args[i + 1] : undefined
}

function envUrl(env: string | undefined, url: string | undefined): string {
  if (url) return url.replace(/\/+$/, '')
  if (env && DEPLOYMENTS[env]) return DEPLOYMENTS[env]
  throw new Error('the JWKS base URL resolves from --url, or from --env when it is one of: ' + Object.keys(DEPLOYMENTS).join(', '))
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2)
  const env = flagValue(args, 'env')
  const url = flagValue(args, 'url')

  if (cmd === 'verify') {
    const base = envUrl(env, url)
    const expectKids = (flagValue(args, 'expect-kids') ?? '').split(',').map(s => s.trim()).filter(Boolean)
    const absentKids = (flagValue(args, 'absent-kids') ?? '').split(',').map(s => s.trim()).filter(Boolean)
    if (!expectKids.length && !absentKids.length) throw new Error('verify needs --expect-kids and/or --absent-kids')
    const { advertised } = await pollJwksKids(base, { expectKids, absentKids })
    console.log(`ok — ${base}/jwks.json advertises exactly the expected state (kids: ${advertised.join(', ') || 'none'})`)
    return
  }

  if (cmd === 'retirement-note') {
    const kid = flagValue(args, 'kid')
    if (!env || !kid) throw new Error('retirement-note needs --env <env> --kid <kid>')
    console.log(buildRetirementNote({ env, kid, retireAfterHours: Number(flagValue(args, 'retire-after-hours') ?? DEFAULT_RETIRE_AFTER_HOURS), url: envUrl(env, url) }))
    return
  }

  if (cmd !== 'rotate') {
    console.error('usage: npx tsx scripts/op-key-rotate.ts <rotate|verify|retirement-note> [flags]')
    process.exit(2)
  }
  if (!env) throw new Error('rotate needs --env <identity|identity-preview> (the Worker the secret lands on)')
  if (!DEPLOYMENTS[env] && !url) throw new Error(`unknown --env ${env} — pass --url explicitly for a non-standard target (the local-stack test posture)`)
  const base = envUrl(env, url)
  const apply = args.includes('--apply')
  const retireAfterHours = Number(flagValue(args, 'retire-after-hours') ?? DEFAULT_RETIRE_AFTER_HOURS)

  // 1. The overlap baseline: the incumbent kids. A rotation NEVER starts
  //    blind against a live deployment (an unreachable JWKS under
  //    --apply is an honest refusal, not a guess).
  let incumbent: string[] = []
  try {
    incumbent = await fetchJwksKids(base)
    console.log(`incumbent JWKS kids at ${base}: ${incumbent.join(', ') || '(none yet)'}`)
  } catch (e) {
    if (apply) throw new Error(`cannot read the incumbent JWKS (${(e as Error).message}) — --apply refuses to rotate blind. Fix the reachability first, or run without --apply for the manual ceremony.`)
    console.warn(`WARNING: the incumbent JWKS is unreachable (${(e as Error).message}) — the overlap assert will run against the new kid only`)
  }

  // 2. The successor pair.
  const successor = await generateSuccessorPair()
  console.log(`successor key generated: kid ${successor.kid} (ES256, P-256)`)

  if (!apply) {
    // The manual ceremony: the private material prints ONCE, here, and
    // the operator drives the secret store by the printed instruction.
    console.log([
      '',
      '── the secret material (prints ONCE; never committed, never logged) ──',
      successor.privateJwkJson,
      '── end of the secret material ──',
      '',
      'Declare it (stdin, so the material never rides argv or a shell history):',
      '',
      `  npx wrangler secret put OP_SIGNING_KEY --env ${env}`,
      `  (paste the JSON above at the prompt, then Enter)`,
      '',
      'or rerun this ceremony with --apply and the script drives the put itself.',
      '',
      'Then assert the overlap:',
      '',
      `  npx tsx scripts/op-key-rotate.ts verify --url ${base} --expect-kids ${[...incumbent, successor.kid].join(',')}`,
      '',
    ].join('\n'))
  } else {
    applySigningKeySecret(env, successor.privateJwkJson)
    console.log(`OP_SIGNING_KEY declared on --env ${env} (the worker restarts on the secret update)`)
  }

  // 4. The overlap assert: the JWKS must advertise BOTH the incumbents
  //    and the successor before anything may retire. (The poll itself is
  //    the new key's first-use registration trigger; --apply mode runs it
  //    now, the manual path prints the command above.)
  if (apply) {
    const { advertised } = await pollJwksKids(base, { expectKids: [...incumbent, successor.kid] })
    console.log(`overlap proven: JWKS advertises ${advertised.join(', ')}`)
  }

  // 5. The retirement note for every incumbent row.
  for (const kid of incumbent) {
    console.log(buildRetirementNote({ env, kid, retireAfterHours, url: base }))
  }
  if (!incumbent.length) console.log('(no incumbent keys — a first declaration; nothing to retire)')
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  main().catch(e => {
    console.error(`op-key-rotate failed: ${e instanceof Error ? e.message : String(e)}`)
    process.exit(1)
  })
}
