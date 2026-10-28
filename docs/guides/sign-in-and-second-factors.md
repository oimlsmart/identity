# Signing in and second factors

This guide describes how signing in works on the OIML SMART identity service, why a second verification step is required, and how each factor behaves. It is written for account holders and for administrators who support them. The cryptographic mechanisms referenced here are the W3C Web Authentication specification (passkeys), RFC 6238 (TOTP one-time codes), and RFC 8176 (the authentication method recording that the service attaches to every session).

## Two-step verification and why the service requires it

The service uses two-step verification: the first step proves knowledge of the password, and the second step proves possession of a registered factor. A password is a single reusable secret; it is exposed to phishing, to reuse across services, and to corpus breaches. When a second factor is registered on an account, the password alone never opens a session. The password verifies into a short-lived pending challenge, and the session is minted only after the second proof completes.

The service records which proofs completed each sign-in. The record follows RFC 8176 and names the methods in use, for example `["pwd", "totp"]` for a password with an authenticator code, or `["webauthn"]` for a passkey. Relying parties receive the same provenance in the issued tokens.

## The factors

The service supports four second factors. An account may register any combination of them.

**Passkeys.** A passkey is a credential bound to one device or security key. The credential's private key never leaves the authenticator, and the ceremony is bound to the service's own origin, which makes a passkey assertion useless to a phishing site. A passkey can serve as the second step after a password, or as the only step in a passwordless sign-in.

**Authenticator codes (TOTP).** A time-based one-time code from an authenticator application, per RFC 6238. The code changes every thirty seconds and is accepted once.

**The verified email code.** The service sends a one-time code to the account's verified primary address. For an account with a verified address, this code stands as a permanent second factor. For an account whose primary address is not verified, the code is available only within an allowance that an administrator grants or that follows a completed password reset.

**Recovery codes.** A set of single-use codes issued when the first factor is registered. Each code is used once and is then consumed. The set is shown once at issuance and can be regenerated from the account console.

## The passkey and the second step

A passkey sign-in does not require an additional second step. The reason lies in what a passkey already proves. The ceremony combines possession of the authenticator with user verification, which is performed by the device itself: the biometric, or the device unlock code, releases the signature. The operating system enforces this local unlock under its own policy. A passkey therefore carries two factors in one gesture, and the origin binding supplies phishing resistance that no code-based second factor offers.

The service requests user verification with the `preferred` setting. The platform operating system decides how the local unlock is satisfied on each device. The service does not override that decision.

## The sign-in flow

The password verifies into a pending challenge, and the service then selects the factor step. The selection follows one rule: the passkey leads. When the account holds a passkey, its ceremony starts immediately, and the remaining methods wait behind a single control named "Try another way".

When the passkey ceremony is cancelled, or when the device holds no passkey, the flow does not stop. The chooser takes over automatically and lists every other method the account holds. The verified email code is selected from the chooser, the code arrives by mail, and the sign-in completes. Recovery codes remain reachable behind the panes, and the password reset remains available from the sign-in page as the recovery path of last resort.

A holder who completes the second step may select "Remember this browser for 14 days". The choice stores a device-scoped trust marker, and the second step is not asked again on that browser while the marker lives. Any password change, password reset, or deactivation clears every trust marker on the account.

## Session provenance and the security bounds

Every completed sign-in lands on the account's activity feed with the method, the device summary, the origin country, and the new-device and country-change advisories. A failed password attempt pays a bounded wait that grows with the failure count, notifies the holder at most once per hour, and lands on the same audit chain. A burned attempt limit on the second-factor step notifies the holder and locks the attempt.

Sensitive acts in the account console demand a fresh proof: the address changes, the factor removals, the password removal, and the token mint. A session younger than five minutes satisfies the demand, and the current password or the passkey re-entry extends it for five minutes more. This posture is the service's equivalent of the administrator modes that other platforms name sudo.

## Administrator support paths

An administrator can grant the email-code allowance to an account whose primary address is not verified, which opens the emailed second factor for that account. An administrator can also issue a fresh enrollment link, which sets the password and proves the mailbox in one act. Both acts are audited, and both notify the account holder.
