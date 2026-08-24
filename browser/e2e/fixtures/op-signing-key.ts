// ─────────────────────────────────────────────────────────────────────
// The e2e stacks' DECLARED OP_SIGNING_KEY (oimlsmart/identity#7).
//
// The identity e2e legs simulate DEPLOYMENTS: they declare OP_ISSUER,
// and since the identity#7 registration gate a declared-issuer instance
// never registers a GENERATED development key into oidc_keys (the
// production keyset's pollution wall — routes/op.ts's
// maySelfRegisterOpKey). A stack that round-trips tokens against the
// OP's JWKS (the stub RP's validateIdToken, the surface contract's key
// invariants) therefore declares its signing key exactly like a real
// deployment: a FRESH ES256 pair per leg (never a checked-in key),
// handed to the spawned API as the OP_SIGNING_KEY env. The generation
// is the rotation ceremony's own (scripts/op-key-rotate.ts's
// generateSuccessorPair), so the kid is stamped the OP's way.
//
// Cached per process: each leg runs in its own vitest invocation
// (scripts/e2e-run.ts) and boots its own isolated stack, so one pair
// per leg, no kid ever colliding across legs.
// ─────────────────────────────────────────────────────────────────────

import { generateSuccessorPair } from '../../scripts/op-key-rotate'

let cached: Promise<string> | null = null

/** The leg's OP_SIGNING_KEY declaration (the JWK JSON EC P-256 private
 *  key). Generated once per process; the spawned stack reads it from
 *  the env, exactly like the declared Worker secret. */
export function fixtureOpSigningKey(): Promise<string> {
  cached ??= generateSuccessorPair().then(p => p.privateJwkJson)
  return cached
}
