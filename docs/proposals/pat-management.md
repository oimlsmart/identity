# Proposal: managed personal access tokens — editing permissions and renaming after creation

This proposal defines the token-management capabilities that the personal
access token (PAT) system gains: the ability to edit a token's permission
set after the token has been created, the ability to rename a token after
creation, and the consumer-side integration by which a relying service such
as the OIML SMART AI assistant accepts these tokens. The proposal follows
the permission-model class of GitHub fine-grained personal access tokens
and Cloudflare API tokens, in which a token is a named, scoped and dated
credential whose permissions an owner manages over its lifetime rather than
a secret that can only be discarded and reissued.

## What exists today

Migration 0020 introduced the `personal_access_tokens` table, and the router
`server/routes/op-tokens.ts` serves the account's own console API behind a
signed session. The current capabilities are the following:

- **Minting.** A token is created with a name, a scope set chosen from the
  account's standing permissions and an expiration. The plaintext secret is
  returned exactly once, and the store holds only its SHA-256 hash together
  with a display prefix.
- **Narrowing.** A token's scopes are always a subset of the holder's
  standing permissions, and the narrowing is re-judged live at every
  exchange rather than being fixed at mint time.
- **Org-context pinning.** A token is minted under the console session's
  effective organizational context, and it acts within that context's
  visibility, never wider.
- **Revocation and audit.** A token is revoked by its owner, the row is
  retained for the audit chain, and the mint, refuse and revoke acts land
  on the account's activity feed together with notification email.

The routes that exist today are `GET /api/op/account/tokens` (the
registry), `POST /api/op/account/tokens` (the mint) and
`DELETE /api/op/account/tokens/:id` (the revoke). There is no route that
edits a token after its creation, which is the gap this proposal closes.

## The two new capabilities

### Renaming a token

The console gains `PATCH /api/op/account/tokens/:id` with a `name` field.
The name is presentation-only metadata: it appears in the registry, in the
audit chain and in notification email, and it participates in no
authorization decision. Renaming therefore requires no re-validation
beyond the session gate, the ownership check and the existing name
validation that the mint applies (non-empty, within the length bound, and
unique per account). The act lands on the audit chain with both the former
and the new name, because a rename that is not audited is a rename that
can hide the purpose of a credential.

### Editing the permission set

The same `PATCH` route accepts a `scopes` field carrying the complete
replacement scope set, in the same grammar the mint uses
(`<service>:<action-class>` tokens). The edit applies the mint's
validation exactly: the submitted set must be a subset of the holder's
standing permissions at the moment of the edit, under the session's
effective organizational context. The design consequence is that both
narrowing and widening are safe operations, for the following reason: the
exchange path re-judges the token's scopes against the holder's live
standing on every use, so a token can never hold a permission its holder
no longer has, regardless of what is stored against the row.

An edit that widens a token is audited distinctly from one that narrows
it, and the notification email states the direction of the change, because
widening a credential is a security-relevant act that an owner may wish to
review. An edit against a revoked or expired token is refused, since a
dead credential's permissions are not meaningfully editable.

No migration is required: the `scopes` and `name` columns exist, and the
change is two store methods (`renamePersonalAccessToken`,
`updatePersonalAccessTokenScopes`) plus the route, the audit events and
the console surface.

## The permission-model class this follows

The model is the class that GitHub fine-grained tokens and Cloudflare API
tokens established: a token carries a name for recognition, a permission
set expressed against named services, an expiration for bounded life, an
org context for visibility, and a management surface over its lifetime.
The estate's variant differs from both vendors in one respect that is a
strength: the narrowing against the holder's standing is re-computed at
every exchange, so permission drift in the underlying account propagates
into its tokens immediately rather than at the token's next issuance.

## Consumer integration: the relying service

The OIML SMART AI assistant (ai.oimlsmart.org) is the first relying
consumer of these tokens. The integration is the following:

1. **Exchange.** The assistant accepts a PAT as the bearer credential on
   its keyed endpoints. On receipt it presents the token to the identity
   service's exchange endpoint, which resolves the holder, applies the
   live narrowing and returns the effective scope set together with the
   org context. The assistant caches the resolution for a short interval
   and treats the exchange response, never the token's stored scopes, as
   authoritative.
2. **Scope mapping.** The assistant maps the identity scope grammar onto
   its own capability checks: a `rag:read` scope authorizes asking and
   searching, a `rag:write` scope authorizes conversation and memory
   mutation, and an `rag:admin` scope (checked against standing, never
   mintable narrower than the holder's own) authorizes the administrative
   routes. The assistant's existing per-key daily allowances apply per
   token.
3. **Coexistence.** The assistant's administrator-issued API keys remain
   valid for machine callers that belong to the service itself. Personal
   access tokens become the user-owned credential, and the assistant's
   console accepts either.

## Testing

The router change lands with the repo's standing gates: unit tests for the
store methods, route tests for the session gate, the ownership refusal,
the subset refusal, the revoked-token refusal and the audit rows, and an
e2e leg covering the console flow of mint, rename, edit, verify and
revoke. The endpoint-scaling gate applies to the registry route, which is
unchanged.
