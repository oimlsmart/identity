// ─────────────────────────────────────────────────────────────────────
// op-heartbeat.ts — the identity service's independent availability
// probe (TODO.identity-ops/04; the operating plan is docs/deployment/
// identity-operations.md, PR #175). Runs from the identity-heartbeat
// workflow every 15 minutes; a red probe opens or updates the standing
// issue (the demo-reset report-failure pattern).
//
// The probe is the OIDC-surface contract's PUBLIC legs
// (scripts/op-surface-contract.ts's probe mode) plus the synthetic
// RP-side claim shape: what a Relying Party actually needs from the OP
// must hold, or the probe is red even when every endpoint answers:
//
//   1. the discovery document serves, its issuer IS the probed origin,
//      the four endpoints ride under it, and the code flow + S256 +
//      ES256 are advertised (an RP's boot depends on all three);
//   2. the JWKS serves at least one well-shaped ES256 key (the RP's
//      token validation depends on it);
//   3. claims_supported covers the synthetic RP claim shape: the OIDC
//      core (iss/sub/aud/exp/iat/nonce) + profile/email + the
//      federation's role claims (roles/groups/org — the committed RP
//      wirings read groups + roles, src/__tests__/id-04-wiring.test.ts);
//   4. the error taxonomy stays honest (the token endpoint refuses
//      cleanly, userinfo demands the Bearer token).
//
// Usage (from browser/):  npx tsx scripts/op-heartbeat.ts [baseUrl]
// Exit 0 = every leg green; any failure exits 1 naming the leg.
// ─────────────────────────────────────────────────────────────────────

import { captureSurface, assertSurfaceInvariants } from './op-surface-contract'

const BASE_URL = (process.argv[2] ?? 'https://id.oimlsmart.org').replace(/\/+$/, '')

/** The synthetic RP-side claim shape: the claims an RP's validator +
 *  claim mapping need the OP to advertise. */
const RP_REQUIRED_CLAIMS = [
  'iss', 'sub', 'aud', 'exp', 'iat', 'nonce',
  'name', 'email', 'email_verified',
  'roles', 'groups', 'org',
]

let failures = 0
function ok(leg: string, detail = '') {
  console.log(`  ok — ${leg}${detail ? ` (${detail})` : ''}`)
}
function fail(leg: string, detail = '') {
  failures++
  console.error(`  FAIL — ${leg}${detail ? `: ${detail}` : ''}`)
}

async function main(): Promise<void> {
  console.log(`identity heartbeat against ${BASE_URL} (${new Date().toISOString()})`)

  let captured: Record<string, unknown>
  try {
    captured = await captureSurface(BASE_URL, null)
  } catch (e) {
    fail('the OP serves at all', (e as Error).message)
    process.exit(1)
  }
  ok('the discovery document + JWKS serve')

  // The contract's public invariants (discovery shape, JWKS key shape,
  // the error taxonomy's redirect discipline).
  const problems = assertSurfaceInvariants(captured, BASE_URL)
  problems.length === 0
    ? ok('the surface invariants hold')
    : fail('the surface invariants hold', problems.join('; '))

  // The synthetic RP claim shape.
  const discovery = captured.discovery as Record<string, unknown>
  const claimsSupported = new Set((discovery.claims_supported ?? []) as string[])
  const missingClaims = RP_REQUIRED_CLAIMS.filter(c => !claimsSupported.has(c))
  missingClaims.length === 0
    ? ok('the RP-side claim shape (claims_supported covers the RP contract)')
    : fail('the RP-side claim shape', `claims_supported lost: ${missingClaims.join(', ')}`)

  const algs = (discovery.id_token_signing_alg_values_supported ?? []) as string[]
  algs.includes('ES256')
    ? ok('ES256 token signing advertised')
    : fail('ES256 token signing advertised', JSON.stringify(algs))
  const challenges = (discovery.code_challenge_methods_supported ?? []) as string[]
  challenges.includes('S256')
    ? ok('PKCE S256 advertised')
    : fail('PKCE S256 advertised', JSON.stringify(challenges))

  if (failures > 0) {
    console.error(`identity heartbeat: ${failures} leg(s) FAILED`)
    process.exit(1)
  }
  console.log('identity heartbeat: all legs green')
}

main().catch(e => {
  console.error(`identity heartbeat failed to run: ${e instanceof Error ? e.message : String(e)}`)
  process.exit(1)
})
