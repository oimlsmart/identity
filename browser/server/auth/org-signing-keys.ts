// ═══════════════════════════════════════════════════════════════════
// The org signing keys (TODO.trust-registry/01): a signing key is an ORG
// ACCOUNT'S property on the OP — never a deployment secret, never an
// unattributed row. The OP is the root of trust for WHO signs: a
// verifier resolves the signer's key against the org's published key set
// and the org's standing in one request (routes/op-keys.ts's PUBLIC
// endpoint); the platform is the record of WHAT was signed.
//
// THE CUSTODY RULE: the OP holds the PUBLIC half (ES256, P-256) plus the
// custody metadata (the label, the created/rotated/revoked stamps, the
// actor on each act). The PRIVATE material is NEVER stored — the org
// keeps it; a registration body carrying a private field is refused at
// the door (validateOrgSigningPublicJwk).
//
// THE KID: derived the OP's own way (auth/op/keys.ts's kidFor — SHA-256
// over the coordinates), so the signer and the OP always agree on the
// key id and a re-registration of the same coordinates is the honest
// duplicate, never a second row.
//
// THE OVERLAP DOCTRINE (op-key-rotate.ts applied to org keys): a
// rotation REGISTERS THE SUCCESSOR and stamps the predecessor
// (rotated_at/by + successor_kid) — the predecessor's row STAYS, still
// resolving, so an artifact signed before the rotation verifies. A
// revocation stamps revoked_at/by and STILL keeps the row: the verify
// answer is "valid at the time; the key since revoked on DATE". Rows
// are never deleted.
//
// THE STORAGE: the entity store's generic seam (the orgEndorsements
// precedent, TODO.register/01) — the orgSigningKeys collection is a
// DATA-LEVEL extension, no store-seam change, no migration.
//
// WORKER-SAFE: the ServerStore seam only — no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '@oimlsmart/platform-server/store'
import { kidFor } from './op/keys'

/** The entity-store collection (the generic seam — the same machinery
 *  auditEvents and orgEndorsements ride). */
const SIGNING_KEY_STORE = 'orgSigningKeys'

/** The TS lib's JsonWebKey lacks the JWS header fields the stamped
 *  public half carries (kid/alg/use) — widen it once, locally. */
export type OrgSigningJwk = JsonWebKey & { kid: string; alg: string; use: string }

/** One org's signing key (the PUBLIC half + the custody chain). */
export interface OrgSigningKey {
  kid: string
  /** The org the key belongs to (the registry org's id). */
  orgId: string
  /** The PUBLIC JWK, kid/alg/use stamped. NEVER the private half. */
  publicJwk: OrgSigningJwk
  label: string
  createdAt: string
  createdBy: string | null
  /** The rotation stamps (the overlap doctrine): set when a successor
   *  landed — the row STAYS resolvable for the at-the-time artifacts. */
  rotatedAt: string | null
  rotatedBy: string | null
  successorKid: string | null
  /** The revocation stamps (terminal): the row STILL stays — the verify
   *  answer is "valid at the time; the key since revoked on DATE". */
  revokedAt: string | null
  revokedBy: string | null
}

/** The JWK fields that betray PRIVATE material (RFC 7517/7518: the EC
 *  private coordinate plus the other key types' private members — a
 *  registration carrying any of them is refused at the door). */
const PRIVATE_JWK_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const

/** The registration body's public-JWK validation: an ES256 (EC P-256)
 *  PUBLIC key — the coordinates present, the private material ABSENT.
 *  Answers the refusal reason (the route's honest 400), null when the
 *  JWK is a clean public half. */
export function orgSigningJwkRefusal(jwk: unknown): string | null {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
    return 'public_jwk must be a JSON Web Key object (the PUBLIC half of an ES256 pair)'
  }
  const j = jwk as Record<string, unknown>
  if (j.kty !== 'EC' || j.crv !== 'P-256') {
    return 'public_jwk must be an EC key on the P-256 curve (kty "EC", crv "P-256") — the org signing keys are ES256'
  }
  if (typeof j.x !== 'string' || !j.x || typeof j.y !== 'string' || !j.y) {
    return 'public_jwk carries no public coordinates (x, y)'
  }
  const leaked = PRIVATE_JWK_FIELDS.filter(f => f in j)
  if (leaked.length) {
    return `public_jwk carries PRIVATE material (${leaked.join(', ')}) — the OP never stores the private half; the org keeps it. Send the public JWK only`
  }
  if (j.alg !== undefined && j.alg !== 'ES256') {
    return 'public_jwk’s alg, when declared, is ES256'
  }
  return null
}

function parseSigningKey(data: string): OrgSigningKey | null {
  try {
    const parsed = JSON.parse(data) as OrgSigningKey
    if (typeof parsed?.kid !== 'string' || typeof parsed?.orgId !== 'string' || typeof parsed?.publicJwk !== 'object') return null
    return parsed
  } catch {
    return null
  }
}

/** Every signing-key row of one org (active, rotated, revoked — the
 *  custody chain is the history), oldest first (the resolution order). */
export async function listOrgSigningKeys(store: ServerStore, orgId: string): Promise<OrgSigningKey[]> {
  return (await store.listEntities(SIGNING_KEY_STORE))
    .map(row => parseSigningKey(row.data))
    .filter((k): k is OrgSigningKey => !!k && k.orgId === orgId)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
}

/** One key by org + kid (null when the set does not carry it). */
export async function resolveOrgSigningKey(store: ServerStore, orgId: string, kid: string): Promise<OrgSigningKey | null> {
  const row = await store.getEntity(SIGNING_KEY_STORE, `${orgId}:${kid}`)
  const key = row ? parseSigningKey(row.data) : null
  return key && key.orgId === orgId && key.kid === kid ? key : null
}

/** Register the org's signing key (the PUBLIC half only — the refusal
 *  runs in the route). The kid derives the OP's own way; the duplicate
 *  (same coordinates already registered to this org) answers null. */
export async function registerOrgSigningKey(
  store: ServerStore,
  input: { orgId: string; publicJwk: JsonWebKey; label: string; createdBy: string | null },
): Promise<OrgSigningKey | null> {
  const kid = await kidFor(input.publicJwk)
  if (await resolveOrgSigningKey(store, input.orgId, kid)) return null
  const key: OrgSigningKey = {
    kid,
    orgId: input.orgId,
    publicJwk: { kty: 'EC', crv: 'P-256', x: input.publicJwk.x, y: input.publicJwk.y, kid, alg: 'ES256', use: 'sig' },
    label: input.label,
    createdAt: new Date().toISOString(),
    createdBy: input.createdBy,
    rotatedAt: null,
    rotatedBy: null,
    successorKid: null,
    revokedAt: null,
    revokedBy: null,
  }
  await store.putEntity(SIGNING_KEY_STORE, `${input.orgId}:${kid}`, input.orgId, JSON.stringify(key))
  return key
}

/** Rotate: register the SUCCESSOR and stamp the predecessor (the overlap
 *  doctrine) — the predecessor's row stays resolvable with rotated_at/by
 *  + successor_kid, so the at-the-time artifacts keep verifying. Answers
 *  null when the successor's coordinates duplicate an existing row (the
 *  route's honest 409). The predecessor resolution + its refusal states
 *  are the route's. */
export async function rotateOrgSigningKey(
  store: ServerStore,
  predecessor: OrgSigningKey,
  input: { publicJwk: JsonWebKey; label: string; actor: string | null },
): Promise<{ predecessor: OrgSigningKey; successor: OrgSigningKey } | null> {
  const successor = await registerOrgSigningKey(store, {
    orgId: predecessor.orgId,
    publicJwk: input.publicJwk,
    label: input.label,
    createdBy: input.actor,
  })
  if (!successor) return null
  const stamped: OrgSigningKey = {
    ...predecessor,
    rotatedAt: new Date().toISOString(),
    rotatedBy: input.actor,
    successorKid: successor.kid,
  }
  await store.putEntity(SIGNING_KEY_STORE, `${predecessor.orgId}:${predecessor.kid}`, predecessor.orgId, JSON.stringify(stamped))
  return { predecessor: stamped, successor }
}

/** Revoke: the terminal stamps land on the row — NEVER a delete (the
 *  at-the-time honesty: an artifact signed before the revocation still
 *  resolves, and the answer names the revocation date). Answers the
 *  updated row, null when the id is unknown. */
export async function revokeOrgSigningKey(store: ServerStore, orgId: string, kid: string, actor: string | null): Promise<OrgSigningKey | null> {
  const key = await resolveOrgSigningKey(store, orgId, kid)
  if (!key) return null
  const revoked: OrgSigningKey = { ...key, revokedAt: new Date().toISOString(), revokedBy: actor }
  await store.putEntity(SIGNING_KEY_STORE, `${orgId}:${kid}`, orgId, JSON.stringify(revoked))
  return revoked
}
