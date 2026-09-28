// ═══════════════════════════════════════════════════════════════════
// The self-registration's link tokens (the 2026-09-26 flow): a
// SELF-CONTAINED, time-bound HMAC token bound to the receiving email
// address. No pending-intent rows exist anywhere — the entire
// registration intent rides in the emailed link, and nothing is stored
// until the verified click (the owner's law).
//
//   token = base64url({ e: email, iat, exp }).<hmac>
//
// The key material is the OP signing key's own secret (the same
// material the upstream state module signs with) — the OP's trust
// anchor asserts "this service invited this address", nothing more.
// One-time-ness is enforced by the account's own existence: a replayed
// token finds the dup email and answers the honest
// already-registered sentence.
//
// WORKER-SAFE: WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

const REGISTRATION_TTL_MS = 24 * 60 * 60 * 1000
/** The setup proof's own short window (the 2026-09-29 second
 *  verification): the fresh sign-in's answer, never the emailed link
 *  alone, unlocks the completion. */
const SETUP_PROOF_TTL_MS = 15 * 60 * 1000

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlDecode(s: string): string {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  return atob(b64)
}

async function hmacSha256(key: string, message: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message))
  return base64url(new Uint8Array(sig))
}

/** Constant-time string equality (the github.ts discipline). */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

export interface RegistrationTokenPayload {
  /** The target email — the token is bound to THIS address. */
  e: string
  /** The applicant's name (the start form's own claim, signed and
   *  carried to the setup step — no state between the legs). */
  n?: string
  /** The upstream ATTRIBUTION binding: the salted hash of
   *  (provider, upstream account id) — the second sign-in must
   *  reproduce it, so a forwarded link is unwired and one upstream
   *  account cannot complete an attribution it did not make. Never
   *  the raw id. */
  a?: string
  /** The SECOND-PROOF mark: set only on the token the second sign-in
   *  mints; the completion accepts nothing else. */
  s?: boolean
  /** The proof token's RAW upstream identity (the s-mark form only):
   *  the completion links it as the account's own sign-in method (the
   *  2026-09-29 ruling). The OP signed it; the browser held it for the
   *  15-minute window at most. */
  p?: string
  u?: string
  iat: number
  exp: number
}

/** The attribution binding: HMAC(secret, provider \u0000 accountId) —
 *  deterministic per (deployment, provider, upstream account), never
 *  carrying the raw id in any artifact. */
export async function attributionHash(secretMaterial: string, provider: string, accountId: string): Promise<string> {
  return hmacSha256(secretMaterial, provider + '\u0000' + accountId)
}

/** Mint the registration token: the email + the 24-hour window, signed.
 *  `now` is injectable for the expiry tests. */
export async function mintRegistrationToken(
  secretMaterial: string,
  email: string,
  now: number = Date.now(),
  ttlMs: number = REGISTRATION_TTL_MS,
  name?: string,
  at?: string,
): Promise<string> {
  const payload: RegistrationTokenPayload = {
    e: email,
    ...(name ? { n: name } : {}),
    ...(at ? { a: at } : {}),
    iat: now,
    exp: now + ttlMs,
  }
  const body = base64url(new TextEncoder().encode(JSON.stringify(payload)))
  const sig = await hmacSha256(secretMaterial, body)
  return `${body}.${sig}`
}

/** Mint the setup PROOF token — the second sign-in's answer. Short-
 *  lived, s-marked, bound to the same email + attribution hash; the
 *  completion accepts nothing else. */
export async function mintSetupProofToken(
  secretMaterial: string,
  email: string,
  at: string,
  now: number = Date.now(),
  ttlMs: number = SETUP_PROOF_TTL_MS,
  name?: string,
  upstream?: { provider: string; accountId: string },
): Promise<string> {
  const payload: RegistrationTokenPayload = {
    e: email, a: at, s: true,
    ...(name ? { n: name } : {}),
    ...(upstream ? { p: upstream.provider, u: upstream.accountId } : {}),
    iat: now,
    exp: now + ttlMs,
  }
  const body = base64url(new TextEncoder().encode(JSON.stringify(payload)))
  const sig = await hmacSha256(secretMaterial, body)
  return `${body}.${sig}`
}

/** Verify the setup proof: the s-mark REQUIRED (a link token never
 *  completes), unexpired, constant-time. Answers { email, at }. */
export async function verifySetupProof(
  secretMaterial: string,
  presented: string,
  opts?: { now?: number },
): Promise<{ email: string; at: string; name: string | null; upstream: { provider: string; accountId: string } | null } | null> {
  const parts = presented.split('.')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null
  let payload: RegistrationTokenPayload
  try {
    payload = JSON.parse(base64urlDecode(parts[0]!)) as RegistrationTokenPayload
  } catch {
    return null
  }
  if (payload.s !== true || typeof payload.e !== 'string' || typeof payload.a !== 'string'
    || typeof payload.iat !== 'number' || typeof payload.exp !== 'number') return null
  const expected = await hmacSha256(secretMaterial, parts[0]!)
  if (!timingSafeEqual(expected, parts[1]!)) return null
  const now = opts?.now ?? Date.now()
  if (now >= payload.exp) return null
  return {
    email: payload.e,
    at: payload.a,
    name: typeof payload.n === 'string' && payload.n.trim() ? payload.n.trim() : null,
    upstream: typeof payload.p === 'string' && typeof payload.u === 'string' ? { provider: payload.p, accountId: payload.u } : null,
  }
}

/** Verify a presented token: well-formed, unexpired, the signature
 *  constant-time. Answers the payload's email on success, NULL
 *  otherwise (tampered, expired, malformed — one uniform null, never a
 *  distinguishable why). */
export async function verifyRegistrationToken(
  secretMaterial: string,
  presented: string,
  opts?: { now?: number },
): Promise<string | null> {
  const parts = presented.split('.')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null
  let payload: RegistrationTokenPayload
  try {
    payload = JSON.parse(base64urlDecode(parts[0]!)) as RegistrationTokenPayload
  } catch {
    return null
  }
  if (typeof payload.e !== 'string' || !payload.e.includes('@')
    || typeof payload.iat !== 'number' || typeof payload.exp !== 'number') return null
  const expected = await hmacSha256(secretMaterial, parts[0]!)
  if (!timingSafeEqual(expected, parts[1]!)) return null
  const now = opts?.now ?? Date.now()
  if (now >= payload.exp) return null
  return payload.e
}

/** The verified payload — the email AND the carried name (the setup
 *  step's display), or NULL on any failure. */
export async function verifyRegistrationPayload(
  secretMaterial: string,
  presented: string,
  opts?: { now?: number },
): Promise<{ email: string; name: string | null; at: string | null; secondProof: boolean } | null> {
  const email = await verifyRegistrationToken(secretMaterial, presented, opts)
  if (!email) return null
  const parts = presented.split('.')
  try {
    const payload = JSON.parse(base64urlDecode(parts[0]!)) as RegistrationTokenPayload
    return {
      email,
      name: typeof payload.n === 'string' && payload.n.trim() ? payload.n.trim() : null,
      at: typeof payload.a === 'string' ? payload.a : null,
      secondProof: payload.s === true,
    }
  } catch {
    return { email, name: null, at: null, secondProof: false }
  }
}
