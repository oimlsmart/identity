// ═══════════════════════════════════════════════════════════════════
// Client-secret hashing for the OIDC Provider (TODO.identity/01) —
// PBKDF2-HMAC-SHA256 over WebCrypto, so BOTH runtimes (node ≥ 18, the
// Worker) execute the identical code path. bcrypt stays with the
// node-only demo-password module (db/store.ts); nothing node-only may
// enter the Worker bundle.
//
// Format: pbkdf2:<iterations>:<base64url salt>:<base64url hash> —
// self-describing, so a cost change never strands a registered client.
//
// WORKER-SAFE: WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

export const OP_SECRET_PBKDF2_ITERATIONS = 100_000

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Constant-time equality (no crypto.timingSafeEqual on Workers — the
 *  length check leaks only what the caller already knows). */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

async function pbkdf2(secret: string, salt: Uint8Array, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'PBKDF2',
    false,
    ['deriveBits'],
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    key,
    256,
  )
  return base64url(new Uint8Array(bits))
}

/** The generic self-describing hash (pbkdf2:<iterations>:<salt>:<digest>)
 *  — TODO.identity/02's password credentials share the ONE implementation
 *  (auth/passwords.ts), at its own cost factor. */
export async function pbkdf2Hash(secret: string, iterations: number): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const hash = await pbkdf2(secret, salt, iterations)
  return `pbkdf2:${iterations}:${base64url(salt)}:${hash}`
}

/** Verify against a self-describing stored hash. A malformed stored value
 *  never verifies (fail closed). */
export async function pbkdf2Verify(secret: string, stored: string): Promise<boolean> {
  const parts = stored.split(':')
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false
  const iterations = Number(parts[1])
  if (!Number.isInteger(iterations) || iterations <= 0) return false
  // workerd caps PBKDF2 at 100,000 iterations (deriveBits throws
  // NotSupportedError above it) — an over-cap stored hash (e.g. created
  // on node before the cap ruled the cost factor) would 500 the path;
  // name it honestly instead.
  if (iterations > 100_000) {
    throw new Error(`the stored hash's iteration count (${iterations}) exceeds this runtime's PBKDF2 cap (100000) — re-set the credential`)
  }
  let salt: Uint8Array
  try {
    salt = base64urlDecode(parts[2]!)
  } catch {
    return false
  }
  const computed = await pbkdf2(secret, salt, iterations)
  return timingSafeEqual(computed, parts[3]!)
}

/** Hash a client secret for the registry (fresh random salt). */
export async function hashClientSecret(secret: string): Promise<string> {
  return pbkdf2Hash(secret, OP_SECRET_PBKDF2_ITERATIONS)
}

/** Verify a presented secret against the stored hash. A malformed stored
 *  value never verifies (fail closed). */
export async function verifyClientSecret(secret: string, stored: string): Promise<boolean> {
  return pbkdf2Verify(secret, stored)
}
