// ═══════════════════════════════════════════════════════════════════
// The passkey ceremonies' client half (TODO.identity-sso/02) — the
// browser-side plumbing between the server's JSON options (base64url
// strings) and the navigator.credentials API (ArrayBuffers). No
// dependency: the WebAuthn API is the platform's.
//
//   register(optionsJson)   — navigator.credentials.create (the console's
//                             enrollment), answering the credential JSON
//                             the server verifies + stores;
//   authenticate(optionsJson, { mediation }) — navigator.credentials.get:
//                             the passwordless button (mediation
//                             'optional') and the conditional-UI autofill
//                             (mediation 'conditional', the caller's
//                             AbortController cancels it when the form
//                             wins);
//   webauthnAvailable() / conditionalUiAvailable() — the progressive-
//                             enhancement probes.
//
// ═══════════════════════════════════════════════════════════════════

// ── base64url ↔ bytes ────────────────────────────────────────────────

export function b64uToBytes(text: string): Uint8Array {
  const clean = text.replace(/-/g, '+').replace(/_/g, '/')
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4)
  const bin = atob(padded)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function bytesToB64u(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let bin = ''
  for (const b of view) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ── the JSON option shapes (the server's answers) ────────────────────

interface PublicKeyCredentialDescriptorJson {
  type: 'public-key'
  id: string
  transports?: string[]
}

export interface RegistrationOptionsJson {
  challenge: string
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>
  attestation: 'none'
  authenticatorSelection: {
    residentKey: 'required'
    requireResidentKey: boolean
    userVerification: string
  }
  excludeCredentials: PublicKeyCredentialDescriptorJson[]
  timeout: number
}

export interface AssertionOptionsJson {
  challenge: string
  rpId: string
  allowCredentials: PublicKeyCredentialDescriptorJson[]
  userVerification: string
  timeout: number
}

export interface CredentialJson {
  id: string
  response: {
    clientDataJSON: string
    attestationObject?: string
    authenticatorData?: string
    signature?: string
    userHandle?: string | null
  }
  transports?: string[]
}

export function webauthnAvailable(): boolean {
  return typeof window !== 'undefined' && typeof navigator !== 'undefined'
    && !!navigator.credentials && typeof PublicKeyCredential !== 'undefined'
}

/** Conditional UI (the passkey autofill on the identifier field): the
 *  progressive enhancement — probed, never assumed. */
export async function conditionalUiAvailable(): Promise<boolean> {
  if (!webauthnAvailable()) return false
  if (typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') return false
  try {
    return await PublicKeyCredential.isConditionalMediationAvailable()
  } catch {
    return false
  }
}

/** The registration ceremony. Throws the DOMException the authenticator
 *  raised (the page maps it to plain language). */
export async function registerPasskey(options: RegistrationOptionsJson): Promise<CredentialJson> {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: b64uToBytes(options.challenge) as BufferSource,
      rp: { id: options.rp.id, name: options.rp.name },
      user: {
        id: b64uToBytes(options.user.id) as BufferSource,
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams.map(p => ({ type: p.type, alg: p.alg })),
      attestation: options.attestation,
      authenticatorSelection: {
        residentKey: options.authenticatorSelection.residentKey,
        requireResidentKey: options.authenticatorSelection.requireResidentKey,
        userVerification: options.authenticatorSelection.userVerification as UserVerificationRequirement,
      },
      excludeCredentials: options.excludeCredentials.map(d => ({
        type: d.type,
        id: b64uToBytes(d.id) as BufferSource,
        transports: d.transports as AuthenticatorTransport[] | undefined,
      })),
      timeout: options.timeout,
    },
  }) as PublicKeyCredential | null
  if (!credential) throw new Error('the authenticator answered no credential')
  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id ? credential.id : bytesToB64u(new Uint8Array(credential.rawId)),
    response: {
      clientDataJSON: bytesToB64u(new Uint8Array(response.clientDataJSON)),
      attestationObject: bytesToB64u(new Uint8Array(response.attestationObject)),
    },
    transports: typeof response.getTransports === 'function' ? response.getTransports() : [],
  }
}

/** The assertion ceremony. `mediation: 'conditional'` is the
 *  conditional-UI path (the autofill) and REQUIRES the caller's
 *  AbortSignal so a form submission can cancel the wait. */
export async function assertPasskey(
  options: AssertionOptionsJson,
  opts?: { mediation?: CredentialMediationRequirement; signal?: AbortSignal },
): Promise<CredentialJson> {
  const credential = await navigator.credentials.get({
    mediation: opts?.mediation,
    signal: opts?.signal,
    publicKey: {
      challenge: b64uToBytes(options.challenge) as BufferSource,
      rpId: options.rpId,
      allowCredentials: options.allowCredentials.map(d => ({
        type: d.type,
        id: b64uToBytes(d.id) as BufferSource,
        transports: d.transports as AuthenticatorTransport[] | undefined,
      })),
      userVerification: options.userVerification as UserVerificationRequirement,
      timeout: options.timeout,
    },
  }) as PublicKeyCredential | null
  if (!credential) throw new Error('the authenticator answered no credential')
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id ? credential.id : bytesToB64u(new Uint8Array(credential.rawId)),
    response: {
      clientDataJSON: bytesToB64u(new Uint8Array(response.clientDataJSON)),
      authenticatorData: bytesToB64u(new Uint8Array(response.authenticatorData)),
      signature: bytesToB64u(new Uint8Array(response.signature)),
      userHandle: response.userHandle ? bytesToB64u(new Uint8Array(response.userHandle)) : null,
    },
  }
}
