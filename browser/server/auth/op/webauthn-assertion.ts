// ═══════════════════════════════════════════════════════════════════
// The WebAuthn assertion ceremony's shared verification (the DRY
// extraction, 2026-10-15): the login's second-factor ceremony, the
// passwordless sign-in, and the account console's step-up all judge an
// authenticator's answer the same way — the challenge's one-time row
// consumed atomically FIRST (a replay answers the same refusal), the
// credential's resolution + ownership, the signature over the ceremony
// binding, and the counter's clone guard.
//
// WORKER-SAFE: WebCrypto + the store seam only.
// ═══════════════════════════════════════════════════════════════════
import type { Context } from 'hono'
import { getStore, type WebauthnCredential } from '../../store'
import { clientInfo } from '../../client-info'
import { auditFactor, WEBAUTHN_CHALLENGE_TTL_MS } from './factors'
import { webauthnBindingFor } from '../../routes/op-factors'
import { verifyAssertion, CeremonyError } from './webauthn'

export { WEBAUTHN_CHALLENGE_TTL_MS }

/** The assertion ceremony's shared verification: the challenge's
 *  one-time row, the credential's resolution + ownership, the
 *  signature, the counter's clone guard. Answers { cred } on success;
 *  { error } carries the refusal. The CLONE refusal rides `clone: true`
 *  so the caller answers it directly (already audited — it is a
 *  security signal, never a throttle-ladder failure). `expectedUserId`
 *  binds the credential's owner (null = the passwordless discovery
 *  posture, the credential's own owner stands). */
export async function verifyAssertionFor(
  c: Context,
  credential: { id?: string; response?: { clientDataJSON?: string; authenticatorData?: string; signature?: string; userHandle?: string | null } } | undefined,
  expectedUserId: string | null,
): Promise<{ cred: WebauthnCredential; signCount: number; error: null; clone?: never } | { cred: null; signCount: 0; error: Response; clone?: boolean }> {
  if (!credential?.id || !credential.response?.clientDataJSON || !credential.response?.authenticatorData || !credential.response?.signature) {
    return { cred: null, signCount: 0, error: c.json({ error: 'the assertion carries its id + response (clientDataJSON, authenticatorData, signature)' }, 400) }
  }
  // The challenge the authenticator answered IS the one-time row's key.
  let clientChallenge: string
  try {
    const parsed = JSON.parse(new TextDecoder().decode(
      Uint8Array.from(atob(credential.response.clientDataJSON.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0)),
    )) as { challenge?: unknown }
    if (typeof parsed.challenge !== 'string') return { cred: null, signCount: 0, error: c.json({ error: 'clientDataJSON carries no challenge' }, 400) }
    clientChallenge = parsed.challenge
  } catch {
    return { cred: null, signCount: 0, error: c.json({ error: 'clientDataJSON is not valid base64url JSON' }, 400) }
  }
  const store = getStore()
  // Consumed atomically FIRST: whatever fails below never gets the
  // challenge a second life (a replay answers the same refusal).
  const row = await store.consumeWebauthnChallenge(clientChallenge)
  if (!row || row.kind !== 'assert' || row.userId !== expectedUserId) {
    return { cred: null, signCount: 0, error: c.json({ error: 'the ceremony challenge is unknown, expired, or already used — start the sign-in again' }, 401) }
  }
  const cred = await store.getWebauthnCredential(credential.id)
  if (!cred || (expectedUserId !== null && cred.userId !== expectedUserId)) {
    return { cred: null, signCount: 0, error: c.json({ error: 'this passkey is not registered' }, 401) }
  }
  const binding = webauthnBindingFor(c)
  let assertion: { signCount: number; userVerified: boolean }
  try {
    assertion = await verifyAssertion(
      {
        clientDataJSON: credential.response.clientDataJSON,
        authenticatorData: credential.response.authenticatorData,
        signature: credential.response.signature,
      },
      cred.publicKeyCose,
      { challenge: clientChallenge, origin: binding.origin, rpId: binding.rpId },
    )
  } catch (e) {
    if (e instanceof CeremonyError) return { cred: null, signCount: 0, error: c.json({ error: `the authenticator’s answer did not verify: ${e.message}` }, 401) }
    throw e
  }
  // THE CLONE RULE: the store's guarded advance decides. A regressed
  // counter fails the assertion AND audits the clone signal.
  const advance = await store.advanceWebauthnCounter(cred.credentialId, assertion.signCount, clientInfo(c))
  if (advance !== 'ok') {
    await auditFactor('factor.clone_refused', cred.userId, { userId: cred.userId }, {
      credentialId: cred.credentialId, name: cred.name, presented: assertion.signCount,
    })
    return { cred: null, signCount: 0, clone: true, error: c.json({ error: 'this passkey’s signature counter regressed — a cloned credential is refused. Revoke it from your account page and register the authenticator again.' }, 401) }
  }
  return { cred, signCount: assertion.signCount, error: null }
}
