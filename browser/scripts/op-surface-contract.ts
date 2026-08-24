// ─────────────────────────────────────────────────────────────────────
// op-surface-contract.ts — the OIDC-surface contract gate
// (TODO.identity-ops/01 + /05; the operating plan is
// docs/deployment/identity-operations.md, PR #175).
//
// The OP's PUBLIC surface is a contract every Relying Party depends on:
// the discovery document, the JWKS shape, the claims contract, and the
// error taxonomy. A breaking change must fail CI BEFORE it reaches an
// RP, so this script golden-tests the surface against the committed
// snapshot (browser/e2e/golden/op-surface-contract.golden.json):
//
//   record  capture the surface of a running OP and write the golden
//           (the deliberate act when a change IS intended — the diff is
//           the review surface);
//   check   capture + compare against the golden; every drift path is
//           printed and the exit is non-zero (the CI leg;
//           e2e/op-surface-contract.e2e.ts runs it against a freshly
//           booted local stack);
//   probe   the public invariants only (no golden, no credentials):
//           discovery shape, JWKS key shape, the unauthenticated error
//           taxonomy. The deploy pipeline's preview/production proof and
//           the heartbeat (scripts/op-heartbeat.ts) ride this mode.
//
// The claims legs (the consent context, the ID-token claim set,
// userinfo) need a registered client + a sign-in account; they run when
// the credentials are declared (flags or the OP_CONTRACT_* envs below),
// and skip honestly otherwise.
//
// Usage (from browser/):
//   npx tsx scripts/op-surface-contract.ts record http://localhost:9693 \
//     --client-id fixture-rp --client-secret fixture-rp-secret \
//     --redirect-uri http://127.0.0.1:9694/callback \
//     --email ia@oiml.org --password demo2026
//   npx tsx scripts/op-surface-contract.ts check  <baseUrl> [creds…]
//   npx tsx scripts/op-surface-contract.ts probe  https://id.oimlsmart.org
//
// Env seams (the flag wins): OP_CONTRACT_CLIENT_ID,
// OP_CONTRACT_CLIENT_SECRET, OP_CONTRACT_REDIRECT_URI, OP_CONTRACT_EMAIL,
// OP_CONTRACT_PASSWORD. The probe's known-client refusal legs read
// OP_CONTRACT_KNOWN_CLIENT_ID / OP_CONTRACT_KNOWN_REDIRECT_URI.
// ─────────────────────────────────────────────────────────────────────

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const DEFAULT_GOLDEN = join(dirname(fileURLToPath(import.meta.url)), '..', 'e2e', 'golden', 'op-surface-contract.golden.json')

// The volatile markers: values that legitimately differ per capture (the
// issuer is the deployment's own; kids/coordinates change at rotation;
// sub/iat/exp are per-account/per-instant) are normalized to a marker so
// the golden pins the SHAPE, and the invariant assertions below pin what
// the markers must satisfy.
const M = {
  issuer: '{issuer}',
  kid: '{kid}',
  coord: '{coord}',
  sub: '{sub}',
  ts: '{ts}',
} as const

export interface SurfaceCredentials {
  clientId: string
  clientSecret: string
  redirectUri: string
  email: string
  password: string
}

interface FetchLike {
  (input: string, init?: RequestInit): Promise<Response>
}

// ── small helpers ────────────────────────────────────────────────────

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function pkceS256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const part = token.split('.')[1] ?? ''
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (part.length % 4)) % 4)
  return JSON.parse(atob(b64)) as Record<string, unknown>
}

/** Deep-normalize: replace every occurrence of the issuer (and the other
 *  volatile values) inside the captured JSON. */
function normalize(value: unknown, issuer: string): unknown {
  if (typeof value === 'string') return value.split(issuer).join(M.issuer)
  if (Array.isArray(value)) return value.map(v => normalize(v, issuer))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = normalize(v, issuer)
    return out
  }
  return value
}

/** Stable stringify (sorted keys) so the golden's diffs stay minimal. */
export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`)
    return `{${entries.join(',')}}`
  }
  return JSON.stringify(value)
}

/** The golden diff: one line per drifted leaf path (never a wall of
 *  JSON — the reviewer reads exactly what moved). */
export function diffSurface(expected: unknown, actual: unknown, path = '$', out: string[] = []): string[] {
  if (typeof expected !== typeof actual || (expected === null) !== (actual === null)) {
    out.push(`${path}: type drift — golden ${JSON.stringify(expected)}, captured ${JSON.stringify(actual)}`)
    return out
  }
  if (Array.isArray(expected) && Array.isArray(actual)) {
    if (expected.length !== actual.length) {
      out.push(`${path}: length drift — golden ${expected.length}, captured ${actual.length}`)
      return out
    }
    expected.forEach((v, i) => diffSurface(v, (actual as unknown[])[i], `${path}[${i}]`, out))
    return out
  }
  if (expected && actual && typeof expected === 'object') {
    const eKeys = Object.keys(expected as Record<string, unknown>)
    const aKeys = Object.keys(actual as Record<string, unknown>)
    for (const k of eKeys.filter(k => !aKeys.includes(k))) out.push(`${path}.${k}: missing from the capture (golden has ${JSON.stringify((expected as Record<string, unknown>)[k])})`)
    for (const k of aKeys.filter(k => !eKeys.includes(k))) out.push(`${path}.${k}: NEW in the capture (${JSON.stringify((actual as Record<string, unknown>)[k])}) — an intended addition re-records the golden`)
    for (const k of eKeys.filter(k => aKeys.includes(k))) diffSurface((expected as Record<string, unknown>)[k], (actual as Record<string, unknown>)[k], `${path}.${k}`, out)
    return out
  }
  if (expected !== actual) out.push(`${path}: golden ${JSON.stringify(expected)}, captured ${JSON.stringify(actual)}`)
  return out
}

// ── the capture ──────────────────────────────────────────────────────

interface ProbeResult {
  status: number
  error?: string
  redirected?: boolean
  marker?: boolean
  note?: string
}

/** The unauthenticated error-taxonomy probes (every mode runs these). */
async function captureErrorTaxonomy(base: string, fetchImpl: FetchLike): Promise<Record<string, ProbeResult>> {
  const out: Record<string, ProbeResult> = {}

  const jsonProbe = async (res: Response): Promise<ProbeResult> => {
    const body = await res.json().catch(() => ({})) as { error?: string }
    return { status: res.status, ...(body.error ? { error: body.error } : {}) }
  }

  // The token endpoint speaks authorization_code only, form-encoded only.
  out.token_wrong_grant = await jsonProbe(await fetchImpl(`${base}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
  }))
  out.token_json_body = await jsonProbe(await fetchImpl(`${base}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  }))
  out.token_no_client_auth = await jsonProbe(await fetchImpl(`${base}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=authorization_code&code=whatever',
  }))
  out.token_unknown_client = await jsonProbe(await fetchImpl(`${base}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=authorization_code&code=whatever&client_id=contract-probe-unknown',
  }))

  // userinfo demands the Bearer token, and refuses a bogus one the same way.
  out.userinfo_no_token = await jsonProbe(await fetchImpl(`${base}/op/userinfo`))
  out.userinfo_bogus_token = await jsonProbe(await fetchImpl(`${base}/op/userinfo`, {
    headers: { authorization: 'Bearer contract-probe-bogus' },
  }))

  // The consent API refuses an unknown authorization id.
  out.consent_unknown_id = await jsonProbe(await fetchImpl(`${base}/api/op/consent/contract-probe-unknown`))

  // The open-redirect wall: an unknown client is refused IN PLACE (400,
  // the plain refusal page carrying data-testid="op-authorize-error"),
  // NEVER redirected to.
  const unknownClient = await fetchImpl(`${base}/op/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: 'contract-probe-unknown',
    redirect_uri: 'https://invalid.example/steal',
    scope: 'openid',
    state: 's',
    nonce: 'n',
    code_challenge: 'whatever',
    code_challenge_method: 'S256',
  })}`, { redirect: 'manual' })
  out.authorize_unknown_client = {
    status: unknownClient.status,
    redirected: unknownClient.headers.get('location') !== null,
    marker: (await unknownClient.text()).includes('op-authorize-error'),
  }
  return out
}

/** The refusal legs that need a REGISTERED client (its id + one of its
 *  exact redirect URIs): an unregistered redirect_uri is refused in
 *  place; a non-code response_type and a missing PKCE challenge come
 *  back as error redirects on the client's OWN URI. */
async function captureKnownClientRefusals(base: string, clientId: string, redirectUri: string, fetchImpl: FetchLike): Promise<Record<string, ProbeResult>> {
  const out: Record<string, ProbeResult> = {}
  const authorize = (params: Record<string, string>) => fetchImpl(`${base}/op/authorize?${new URLSearchParams(params)}`, { redirect: 'manual' })

  const badRedirect = await authorize({
    response_type: 'code', client_id: clientId, redirect_uri: 'https://invalid.example/steal',
    scope: 'openid', state: 's', nonce: 'n', code_challenge: 'whatever', code_challenge_method: 'S256',
  })
  out.authorize_unregistered_redirect = {
    status: badRedirect.status,
    redirected: badRedirect.headers.get('location') !== null,
    marker: (await badRedirect.text()).includes('op-authorize-error'),
  }

  const readError = (res: Response): ProbeResult => {
    const location = res.headers.get('location') ?? ''
    const back = location ? new URL(location) : null
    return {
      status: res.status,
      ...(back ? { error: back.searchParams.get('error') ?? undefined } : {}),
      redirected: back?.origin + back?.pathname === redirectUri,
    }
  }
  out.authorize_response_type_token = readError(await authorize({
    response_type: 'token', client_id: clientId, redirect_uri: redirectUri,
    scope: 'openid', state: 's', nonce: 'n', code_challenge: 'whatever', code_challenge_method: 'S256',
  }))
  out.authorize_missing_pkce = readError(await authorize({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
    scope: 'openid', state: 's', nonce: 'n',
  }))
  out.authorize_missing_openid_scope = readError(await authorize({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
    scope: 'profile', state: 's', nonce: 'n', code_challenge: 'whatever', code_challenge_method: 'S256',
  }))
  return out
}

/** The claims contract: a full fetch-level round trip (the id-01 leg-5
 *  pattern, no browser) — demo sign-in, authorize, the consent context,
 *  the allow decision, the code exchange, the decoded ID token, and
 *  userinfo, all normalized against the volatile markers. */
async function captureClaims(base: string, issuer: string, creds: SurfaceCredentials, fetchImpl: FetchLike): Promise<Record<string, unknown>> {
  const login = await fetchImpl(`${base}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: creds.email, password: creds.password }),
  })
  if (!login.ok) throw new Error(`the contract account sign-in answered ${login.status} — is the demo cast seeded on ${base}?`)
  const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0]!
  if (!cookie) throw new Error('the contract account sign-in set no session cookie')

  const verifier = 'contract-verifier-3c6f9d2e1a4b7c8d5e0f1a2b3c4d5e6f'
  const challenge = await pkceS256(verifier)
  const nonce = 'contract-nonce-7f2a1c'
  const authorize = await fetchImpl(`${base}/op/authorize?${new URLSearchParams({
    response_type: 'code', client_id: creds.clientId, redirect_uri: creds.redirectUri,
    scope: 'openid profile email', state: 'contract-state', nonce,
    code_challenge: challenge, code_challenge_method: 'S256',
  })}`, { headers: { cookie }, redirect: 'manual' })
  if (authorize.status !== 302) throw new Error(`authorize answered ${authorize.status} for the signed-in contract account`)
  const consentUrl = new URL(authorize.headers.get('location')!, base)
  const authId = consentUrl.searchParams.get('auth')
  if (!authId) throw new Error(`authorize did not hand over a pending authorization (location: ${consentUrl.pathname})`)

  const consentRes = await fetchImpl(`${base}/api/op/consent/${authId}`, { headers: { cookie } })
  if (!consentRes.ok) throw new Error(`the consent context answered ${consentRes.status}`)
  const consent = await consentRes.json() as Record<string, unknown>

  const decide = await fetchImpl(`${base}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  if (!decide.ok) throw new Error(`the consent decision answered ${decide.status}`)
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')
  if (!code) throw new Error('the allow decision carried no code')

  const exchange = await fetchImpl(`${base}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(creds.clientId)}:${encodeURIComponent(creds.clientSecret)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: creds.redirectUri,
      client_id: creds.clientId, code_verifier: verifier,
    }),
  })
  if (!exchange.ok) throw new Error(`the code exchange answered ${exchange.status}: ${await exchange.text().catch(() => '')}`)
  const tokens = await exchange.json() as { access_token: string; token_type: string; expires_in: number; id_token: string }

  const userinfoRes = await fetchImpl(`${base}/op/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
  if (!userinfoRes.ok) throw new Error(`userinfo answered ${userinfoRes.status} for the fresh access token`)
  const userinfo = await userinfoRes.json() as Record<string, unknown>

  const idToken = decodeJwtPayload(tokens.id_token)
  return normalize({
    consent: {
      client: consent.client,
      scopes: consent.scopes,
      policyClaims: consent.policyClaims,
      roleClaims: consent.roleClaims,
      orgClaim: consent.orgClaim,
      account: consent.account,
      issuerName: consent.issuerName,
    },
    idToken: { ...idToken, sub: M.sub, iat: M.ts, exp: M.ts },
    userinfo: { ...userinfo, sub: M.sub },
    tokenResponse: { token_type: tokens.token_type, expires_in: tokens.expires_in },
  }, issuer)
}

/** Capture the OP's public surface (always) + the claims contract (when
 *  the credentials are declared). Pure fetch; never mutates the target
 *  beyond the one-time code the round trip consumes. */
export async function captureSurface(
  baseUrl: string,
  creds: SurfaceCredentials | null,
  fetchImpl: FetchLike = fetch,
): Promise<Record<string, unknown>> {
  const base = baseUrl.replace(/\/+$/, '')

  const discoveryRes = await fetchImpl(`${base}/.well-known/openid-configuration`)
  if (!discoveryRes.ok) throw new Error(`the discovery document answered ${discoveryRes.status} at ${base}`)
  const discovery = await discoveryRes.json() as Record<string, unknown>
  const issuer = typeof discovery.issuer === 'string' ? discovery.issuer.replace(/\/+$/, '') : base

  const jwksUri = typeof discovery.jwks_uri === 'string' ? discovery.jwks_uri : `${base}/jwks.json`
  const jwksRes = await fetchImpl(jwksUri)
  if (!jwksRes.ok) throw new Error(`the JWKS answered ${jwksRes.status} at ${jwksUri}`)
  const jwks = await jwksRes.json() as { keys?: Array<Record<string, unknown>> }
  const keys = jwks.keys ?? []
  // The golden pins the per-key SHAPE (a rotation's overlap key never
  // changes the shape) plus the key-set invariants as booleans; the
  // count is pinned for the fresh local boot (exactly one key) and only
  // asserted >= 1 by the probe's invariants.
  const normKeys = keys.map(k => normalize({ ...k, kid: M.kid, x: M.coord, y: M.coord }, issuer))
  const uniqueShapes = new Set(normKeys.map(k => stableStringify(k)))
  const coordOk = (v: unknown) => typeof v === 'string' && /^[A-Za-z0-9_-]{43}$/.test(v)

  const errors = await captureErrorTaxonomy(base, fetchImpl)
  // The known-client refusal legs ride the full credentials when declared
  // (the client's exact redirect URI is one of its registered ones).
  if (creds) {
    Object.assign(errors, await captureKnownClientRefusals(base, creds.clientId, creds.redirectUri, fetchImpl))
  }

  const captured: Record<string, unknown> = normalize({
    discovery,
    jwks: {
      keyShape: normKeys[0] ?? null,
      keyCount: keys.length,
      allKeysShareShape: normKeys.length > 0 && uniqueShapes.size === 1,
      kidsDistinct: new Set(keys.map(k => k.kid)).size === keys.length,
      coordsWellFormed: keys.length > 0 && keys.every(k => coordOk(k.x) && coordOk(k.y)),
    },
    errors,
  }, issuer)

  if (creds) {
    captured.claims = await captureClaims(base, issuer, creds, fetchImpl)
  }
  return captured
}

// ── the invariants (every mode; the golden pins the shape, these pin
//    what the markers must satisfy) ──────────────────────────────────

export function assertSurfaceInvariants(captured: Record<string, unknown>, baseUrl: string): string[] {
  const problems: string[] = []
  const base = baseUrl.replace(/\/+$/, '')
  const discovery = captured.discovery as Record<string, unknown>
  if (discovery.issuer !== M.issuer) problems.push(`discovery.issuer drifted from the probed origin: ${JSON.stringify(discovery.issuer)} (expected ${base})`)
  for (const field of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri']) {
    const value = discovery[field]
    if (typeof value !== 'string' || !value.startsWith(M.issuer + '/')) problems.push(`discovery.${field} is not under the issuer: ${JSON.stringify(value)}`)
  }
  const jwks = captured.jwks as { keyShape: Record<string, unknown> | null; keyCount: number; allKeysShareShape: boolean; kidsDistinct: boolean; coordsWellFormed: boolean }
  if (!jwks.keyShape) problems.push('the JWKS advertises NO keys — no RP can validate a token')
  if (!(jwks.keyCount >= 1)) problems.push(`the JWKS key count is ${jwks.keyCount}, expected at least 1`)
  if (jwks.keyShape && !jwks.allKeysShareShape) problems.push('the JWKS keys do not all share the pinned shape (kty/crv/alg/use)')
  if (!jwks.kidsDistinct) problems.push('the JWKS kids are not distinct — token validation would pick an ambiguous key')
  if (!jwks.coordsWellFormed) problems.push('the JWKS coordinates are not 32-byte base64url (P-256 points)')

  // The error taxonomy's redirect discipline: the open-redirect wall
  // refuses UNKNOWN clients and unregistered redirect URIs IN PLACE
  // (never a redirect); a validated request's error rides back to the
  // client's OWN registered URI.
  const errors = captured.errors as Record<string, ProbeResult>
  for (const leg of ['authorize_unknown_client', 'authorize_unregistered_redirect']) {
    const probe = errors[leg]
    if (!probe) continue
    if (probe.redirected === true) problems.push(`${leg}: the refusal REDIRECTED — the open-redirect wall must refuse in place`)
    if (probe.marker === false) problems.push(`${leg}: the refusal page lost its op-authorize-error marker`)
  }
  for (const leg of ['authorize_response_type_token', 'authorize_missing_pkce', 'authorize_missing_openid_scope']) {
    const probe = errors[leg]
    if (!probe) continue
    if (probe.status !== 302 || probe.redirected !== true) problems.push(`${leg}: the error must redirect back to the client's OWN registered URI (got status ${probe.status})`)
  }

  const claims = captured.claims as Record<string, Record<string, unknown>> | undefined
  if (claims) {
    if (claims.idToken?.sub !== M.sub || claims.userinfo?.sub !== M.sub) problems.push('the sub marker drifted (the capture normalizes it)')
    const policyClaims = (claims.consent?.policyClaims ?? []) as unknown[]
    for (const claim of ['roles', 'groups', 'org']) {
      if (!policyClaims.includes(claim)) problems.push(`the fixture client's policy no longer surfaces ${claim} on the consent page`)
    }
  }
  return problems
}

// ── the CLI ──────────────────────────────────────────────────────────

interface Cli {
  mode: 'record' | 'check' | 'probe'
  baseUrl: string
  golden: string
  creds: SurfaceCredentials | null
  knownClientId?: string
  knownRedirectUri?: string
}

function parseCli(argv: string[]): Cli {
  const [mode, baseUrl, ...rest] = argv
  if ((mode !== 'record' && mode !== 'check' && mode !== 'probe') || !baseUrl) {
    console.error('usage: npx tsx scripts/op-surface-contract.ts <record|check|probe> <baseUrl> [--golden <path>] [--client-id <id> --client-secret <s> --redirect-uri <u> --email <e> --password <p>]')
    process.exit(2)
  }
  const flag = (name: string): string | undefined => {
    const i = rest.indexOf(`--${name}`)
    return i >= 0 ? rest[i + 1] : undefined
  }
  const env = process.env
  const clientId = flag('client-id') ?? env.OP_CONTRACT_CLIENT_ID
  const clientSecret = flag('client-secret') ?? env.OP_CONTRACT_CLIENT_SECRET
  const redirectUri = flag('redirect-uri') ?? env.OP_CONTRACT_REDIRECT_URI
  const email = flag('email') ?? env.OP_CONTRACT_EMAIL
  const password = flag('password') ?? env.OP_CONTRACT_PASSWORD
  const declared = [clientId, clientSecret, redirectUri, email, password].filter(Boolean).length
  let creds: SurfaceCredentials | null = null
  if (declared > 0 && declared < 5) {
    console.error('the claims legs need ALL of client-id/client-secret/redirect-uri/email/password (flags or OP_CONTRACT_* envs) — a partial declaration fails honestly')
    process.exit(2)
  }
  if (declared === 5) creds = { clientId: clientId!, clientSecret: clientSecret!, redirectUri: redirectUri!, email: email!, password: password! }
  return {
    mode,
    baseUrl,
    golden: flag('golden') ?? DEFAULT_GOLDEN,
    creds,
    knownClientId: flag('known-client-id') ?? env.OP_CONTRACT_KNOWN_CLIENT_ID,
    knownRedirectUri: flag('known-redirect-uri') ?? env.OP_CONTRACT_KNOWN_REDIRECT_URI,
  }
}

async function main(): Promise<void> {
  const cli = parseCli(process.argv.slice(2))
  if (cli.mode === 'check' && !cli.creds) {
    console.error('check mode needs the full credentials (the golden pins the claims contract) — for a credential-less probe use probe mode')
    process.exit(2)
  }

  console.log(`op-surface-contract ${cli.mode} against ${cli.baseUrl}${cli.creds ? ' (claims legs: on)' : ' (claims legs: off — no credentials declared)'}`)
  // Probe mode tolerates the deploy propagation window: a fresh deploy
  // or domain attach can take a minute to answer everywhere, so the
  // first capture retries for up to 90s before the honest failure.
  let captured: Record<string, unknown> | null = null
  const deadline = cli.mode === 'probe' ? Date.now() + 90_000 : Date.now()
  for (;;) {
    try {
      captured = await captureSurface(cli.baseUrl, cli.creds)
      break
    } catch (e) {
      if (Date.now() >= deadline) throw e
      console.log(`  … not answering yet (${(e as Error).message.slice(0, 120)}); retrying`)
      await new Promise(r => setTimeout(r, 5_000))
    }
  }
  const surface = captured!

  // The probe's known-client refusal legs (no full round trip needed).
  if (cli.mode === 'probe' && cli.knownClientId && cli.knownRedirectUri) {
    Object.assign(surface.errors as Record<string, unknown>, await captureKnownClientRefusals(cli.baseUrl.replace(/\/+$/, ''), cli.knownClientId, cli.knownRedirectUri, fetch))
  }

  const invariantProblems = assertSurfaceInvariants(surface, cli.baseUrl)

  if (cli.mode === 'record') {
    writeFileSync(cli.golden, JSON.stringify(JSON.parse(stableStringify(surface)), null, 2) + '\n')
    console.log(`recorded the golden at ${cli.golden}`)
    if (invariantProblems.length) {
      console.error(`WARNING — the recorded surface violates the invariants:\n  ${invariantProblems.join('\n  ')}`)
      process.exit(1)
    }
    return
  }

  if (invariantProblems.length) {
    console.error(`FAIL — surface invariants:\n  ${invariantProblems.join('\n  ')}`)
    process.exit(1)
  }
  console.log('  ok — the surface invariants hold')

  if (cli.mode === 'probe') {
    console.log('op-surface-contract probe: all legs green')
    return
  }

  const golden = JSON.parse(readFileSync(cli.golden, 'utf8')) as unknown
  const diffs = diffSurface(golden, surface)
  if (diffs.length) {
    console.error(`FAIL — the OIDC surface drifted from the committed golden (${diffs.length} difference(s)):`)
    for (const d of diffs) console.error(`  ${d}`)
    console.error('If this drift is INTENDED, re-record deliberately: npx tsx scripts/op-surface-contract.ts record <baseUrl> [creds…] — the golden diff is the review surface.')
    process.exit(1)
  }
  console.log('op-surface-contract check: the surface matches the committed golden')
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  main().catch(e => {
    console.error(`op-surface-contract failed to run: ${e instanceof Error ? e.message : String(e)}`)
    process.exit(1)
  })
}
