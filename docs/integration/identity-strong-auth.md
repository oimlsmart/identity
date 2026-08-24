# Strong authentication at the identity service

The per-account factor registry (TODO.identity-sso/02 + /03), live at
the OP since the post-cutover wave: passkeys (WebAuthn), authenticator
apps (TOTP, RFC 6238), and recovery codes. This page is the reference:
the model, the ceremonies, the hard rules, and the decisions' evidence.

## The model

Many factors per account, of several kinds, each named and revocable:

- **Passkeys** (`webauthn_credentials`): the phishing-resistant kind;
  each may serve as the primary method (the passwordless sign-in) or as
  the second factor after the password. The row carries the name, the
  COSE public key, the signature counter, the declared aaguid +
  transports (display hints, see below), created/last-used/last-IP.
- **Authenticator apps** (`totp_secrets`): the classic second factor. A
  row is PENDING until the first valid code verifies (verified_at), then
  active. The enrollment's verify is throttled hard (below).
- **Recovery codes** (`recovery_codes`): generated at the first factor's
  enrollment, shown once, stored hashed (SHA-256 of the normalized code;
  80 bits of random per code, so the unsalted hash resists the offline
  attack), one-time each. Regenerating replaces the set whole and revokes
  the old one, with the audit event.

Deliberately excluded: SMS and voice OTP. SIM-swap and interception are
documented refusals, not oversights.

The recovery floor rule: recovery codes exist to recover FACTORS, so they
arrive with the first one (never as a lone second password). The email
reset stands behind everything: the lost-device path is the remaining
factors plus the email reset, never a lockout.

## The ceremonies

- **The challenge store** (`webauthn_challenges`): one-time, 5-minute TTL,
  consumed atomically. The database is the proof; a challenge is never
  client-side state. The registration's row binds the account; the
  second-factor assertion's row binds the account; the passwordless
  assertion's row binds nobody (the asserted credential id resolves the
  account, and the userHandle must equal the account's `sub`).
- **The pending sign-in** (`mfa_pending`): when the password verifies and
  the account holds factors, the session waits on the factor. One-time,
  5-minute TTL, consumed atomically at completion; the row carries the
  methods proven so far (the amr prefix) and the throttle ladder state.
- **Registration**: attestation `none` (this assurance level never reads
  authenticator provenance; the aaguid + transports are recorded as what
  the browser declared, and the console presents them as hints). The RP
  ID is the issuer's exact host; the origin check is exact equality.
- **Assertion**: the signature verifies against the stored COSE key over
  `authData || SHA-256(clientDataJSON)`; the counter then advances through
  the store's GUARDED update: both zero is a non-counting authenticator,
  otherwise strictly increasing. A regressed counter is the clone signal:
  the assertion fails and `factor.clone_refused` audits.
- **TOTP enrollment**: the otpauth:// URI answers once; the page renders
  the QR locally (src/qr.ts, the in-repo renderer pinned against the
  reference implementation's matrices) and shows the manual secret. The
  secret never leaves the page; no external image service ever sees it.
  The factor activates ONLY on the first valid code.

## The hard rules

- Verification endpoints are rate-limited hard: the OP-surface per-caller
  bucket mounts on them (the authorize/token/login doctrine), AND the
  per-account ladder rides the rows: after N failures the next attempt
  waits 2^N seconds (base OP_MFA_BACKOFF_BASE_MS, default 1 s, cap 30 s);
  at 5 failures the attempt burns (the pending row is consumed), the
  account is emailed (the mfa_locked template), and the audit chain gains
  `factor.mfa_locked` after a `factor.mfa_failed` per failure. The admin
  dashboard's security signals read the same chain.
- One-time means one-time: challenges, the pending sign-in, recovery
  codes. A replay loses the atomic race.
- Every enrollment, revocation, recovery use, and refused clone writes
  its audit event; the console's factors section reads the registry,
  never a cache.
- Enrollment and the recovery regenerate require a verified primary
  address (the wave-E lifecycle state): the recovery path rides the
  mailbox, so an unverified mailbox refuses factors honestly.

## The session's amr provenance

The session row carries the RFC 8176 list (`pwd`, `otp`, `webauthn`,
`hwk`, and the OP-private `recovery`); the consent decision stamps it on
the one-time code, and the token endpoint emits it as the ID token's
`amr` (userinfo answers the same value). The discovery document's
`claims_supported` carries `amr`. An upstream-IdP sign-in records no
OP-side credential event, so its sessions carry no `amr` at all.

## The dependency decision (recorded, deliberate)

The codebase's doctrine is zero-dependency server code (WebCrypto +
fetch). WebAuthn verification needs a CBOR parse, the COSE-to-WebCrypto
key conversion, and the signature verify. The candidate exception was
@simplewebauthn/server; what it buys is the full attestation machine
(packed/fido-u2f/apple formats, x5c chains, the MDS trust stores), and
this OP registers at attestation `none` by design, so the bought surface
would sit unused while the dependency tree entered the Worker bundle.
The hand-rolled surface is bounded and fixed-shape: one CBOR map at
registration, fixed authenticator-data offsets, three COSE algorithms
(ES256 and Ed25519 WebCrypto-native on node 22 and workerd, RS256 for
the Windows Hello class), and the ECDSA DER-to-P1363 transcode.

The proof (src/__tests__/id-webauthn-vectors.test.ts): the CBOR decoder
pinned against the RFC 7049 Appendix A canonical vectors; TOTP against
the RFC 6238 Appendix B SHA-1 rows; Ed25519 against the RFC 8032 section
7.1 known answer; and the full register-then-assert ceremonies against
freshly minted key material per algorithm (the test kit builds exactly
the bytes an authenticator emits). The interop leg: e2e/id-13 drives
Chrome's real WebAuthn stack through the CDP virtual authenticator,
never a mock. The QR renderer (src/qr.ts) is pinned matrix-for-matrix
against the reference implementation (src/__tests__/qr-golden.ts, the
qrcode package's outputs, every mask and the auto choice).
