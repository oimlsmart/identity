// ═══════════════════════════════════════════════════════════════════
// The session-state digest (TODO.modern/03 — the OIDC Session
// Management surface). The RP's poll protocol compares the
// session_state it received at the authorize answer against a
// recomputation on every poll; the recomputation runs HERE, server
// side, against the request's live session. The entropy is the
// session token itself (HttpOnly — no RP can read or guess it), so no
// stored salt is needed; a revoked/absent session simply refuses, and
// the iframe answers the fail-closed 'changed'.
//
// WORKER-SAFE: WebCrypto + btoa only.
// ═══════════════════════════════════════════════════════════════════

const encoder = new TextEncoder()

export function base64UrlEncode(bytes: ArrayBuffer): string {
  let binary = ''
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The spec's digest shape: client_id + ' ' + origin + ' ' + the OP's
 *  browser state. Our browser state IS the session token. */
export async function computeSessionState(clientId: string, origin: string, sessionToken: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`${clientId} ${origin} ${sessionToken}`))
  return base64UrlEncode(digest)
}
