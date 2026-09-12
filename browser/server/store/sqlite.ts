// ═══════════════════════════════════════════════════════════════════
// The SQLite ServerStore (TODO.cs-e2e/14): the node/self-hosted half
// of the backend seam — the SAME sync modules the server always used
// (store.ts + entities.ts, better-sqlite3) exposed through the async
// ServerStore contract the routes consume. Zero behavior change: every
// method delegates one-for-one.
//
// NODE-ONLY: this module imports better-sqlite3 through store.ts. The
// Worker bundle never sees it (the worker entry installs the D1 store
// instead) — the audit the wrangler config documents.
// ═══════════════════════════════════════════════════════════════════

import { fileURLToPath } from 'url'
import {
  authenticateDemo,
  cleanExpiredSessions,
  createLocalUser,
  createOrgJoinRequest,
  createOrgMembership,
  createOrgRegistryOrg,
  createSession,
  decideOrgJoinRequest,
  deleteOrgMembership,
  deleteOrgRegistryOrg,
  deleteSession,
  findPendingOrgJoinRequestByEmail,
  findUserByEmail,
  findUserByProvider,
  getDb,
  getOrgJoinRequest,
  getOrgMembership,
  getOrgRegistryOrg,
  getSessionActiveOrg,
  getSessionUser,
  getUserById,
  listOrgJoinRequests,
  listAllOrgMemberships,
  listOrgMembers,
  listOrgMemberships,
  listOrgRegistryOrgs,
  listUsers,
  provisionSsoUser,
  seedDemoAccounts,
  setOrgMembershipRoles,
  setOrgMembershipState,
  setOrgMembershipCone,
  setOrgRegistryOrgState,
  setSessionActiveOrg,
  setUserActive,
  setUserRoles,
  touchLastLogin,
  updateOrgRegistryOrg,
  updateUserRoleOrg,
} from './sqlite/store'
import {
  deleteEntity,
  getEntity,
  listEntities,
  putEntity,
} from './sqlite/entities'
import {
  consumeOidcCode,
  consumeOidcRefreshToken,
  countOidcAccessTokensForClient,
  countOidcRefreshTokensForClient,
  createOidcAccessToken,
  createOidcAuthorization,
  createOidcCode,
  createOidcRefreshToken,
  decideOidcAuthorization,
  deleteOidcAccessToken,
  deleteOidcRefreshTokensForUserClient,
  getOidcAccessToken,
  getOidcAuthorization,
  getOidcClient,
  listOidcClients,
  listOidcKeys,
  revokeOidcRefreshToken,
  setOidcClientStatus,
  setOidcClientLaunch,
  upsertOidcClient,
  upsertOidcKey,
} from './sqlite/op-store'
import {
  createIdentityLink,
  deleteIdentityLink,
  deleteIdentityProvider,
  findIdentityLink,
  getIdentityProvider,
  listIdentityLinks,
  listIdentityLinksBulk,
  listIdentityProviders,
  setIdentityProviderEnabled,
  upsertIdentityProvider,
} from './sqlite/upstream-store'
import {
  addAccountEmail,
  completeEmailChange,
  completeEnrollment,
  countSignInMethods,
  countSignInMethodsBulk,
  createEmailChangeToken,
  createEnrollmentToken,
  createOpAccount,
  deleteAllUserSessions,
  deleteOpClientRoles,
  deleteOtherSessions,
  deletePasswordHash,
  deleteSessionById,
  eraseOpAccount,
  findUserByAnyEmail,
  getEmailChangeToken,
  getEnrollmentToken,
  getOpClientRoles,
  getPasswordLogin,
  getPendingEmailChange,
  lastAccountSignIns,
  listAccountEmails,
  listAllOpClientRoles,
  listOpClientRoles,
  listOpLiveSessions,
  listUserSessions,
  markAccountEmailVerified,
  removeAccountEmail,
  revokeOpUserCredentials,
  setOpClientRoles,
  setPasswordHash,
  setPrimaryAccountEmail,
  setUserAvatar,
  updateOpAccount,
  updateUserName,
} from './sqlite/op-accounts-store'
import { installStore, type AccountEmail, type AddAccountEmailResult, type AuthUserPayload, type CertificateHolderClaim, type CertificateHolderOrg, type CompleteEmailChangeResult, type CompleteEnrollmentResult, type ConsumeOidcRefreshTokenResult, type EmailChangeToken, type EnrollmentToken, type EntityChange, type EntityListOptions, type EntityRow, type EntityWriteInput, type EventEntityKey, type EventKeyFilter, type EventWriteInput, type FederationPeer, type IdentityApproval, type IdentityLink, type IdentityProvider, type InstrumentRegistration, type InstrumentRegistrationLifecycle, type InstrumentRegistrationScopeStatus, type InstrumentRegistrationWriteInput, type JournalAppend, type NotifyDelivery, type NotifyDeliveryStatus, type NotifyEntityMute, type NotifyInboxState, type NotifyPreferences, type NotifyRule, type OAuthInitialAssignment, type OidcAccessToken, type OidcAuthorization, type OidcClient, type OidcClientLaunch, type OidcCode, type OidcConsentGrant, type OidcKeyRow, type OidcRefreshToken, type OpAccountErasure, type OpClientRoleAssignment, type OpLiveSession, type OrgJoinRequest, type OrgMembership, type OrgMembershipState, type OrgRegistryContact, type OrgRegistryOrg, type OrgRegistryState, type PersonalAccessToken, type PlatformEvent, type ServerStore, type SessionView, type SsoSignInState, type UserAdminRow, type AdvanceCounterResult, type MfaPending, type RecoveryCodeState, type TotpSecret, type WebauthnChallenge, type WebauthnCredential } from '../store'
import {
  advanceWebauthnCounter,
  consumeMfaPending,
  consumeRecoveryCode,
  consumeWebauthnChallenge,
  createMfaPending,
  createTotpSecret,
  createWebauthnChallenge,
  createWebauthnCredential,
  deleteTotpSecret,
  deleteWebauthnCredential,
  getMfaPending,
  getTotpSecret,
  getWebauthnCredential,
  listTotpSecrets,
  listWebauthnCredentials,
  markTotpSecretUsed,
  markTotpSecretVerified,
  recordMfaPendingFailure,
  recordTotpEnrollFailure,
  replaceRecoveryCodes,
  recoveryCodeState,
} from './sqlite/factors-store'
import {
  createPersonalAccessToken,
  findPersonalAccessTokenByHash,
  getPersonalAccessToken,
  listOrgPersonalAccessTokens,
  listPersonalAccessTokens,
  revokePersonalAccessToken,
  stampPersonalAccessTokenUse,
} from './sqlite/pat-store'
import {
  getConsentGrant,
  listConsentGrants,
  listOidcConsentGrantsForClient,
  recordConsentGrant,
  revokeConsentGrant,
} from './sqlite/consent-grants-store'


/** The workflow tables the reset wipe covers (the D1 store's
 *  WIPE_TABLES twin — one rule, two backends): ordinary rowid tables
 *  all, so ranged rounds address rows by a stable rowid window. The
 *  TODO.notify/01 event store wipes with them — its rows reference the
 *  workflow entities a reset removes (the feed's read-time visibility
 *  gate would drop the orphans anyway; wiping keeps the demo honest).
 *  TODO.register/03: the instrument register wipes too — the e2e
 *  isolation contract resets it with the rest of the mutable workflow
 *  state. TODO.notify/04: the delivery store wipes alongside — its rows
 *  reference the wiped events (the per-recipient record is the
 *  workflow's, never the user's own state). */
const WIPE_TABLES = ['entity_changes', 'evidence_records', 'entities', 'events', 'instrument_registrations', 'notify_deliveries'] as const

export function createSqliteServerStore(): ServerStore {
  return {
    // ── users / sessions ──
    async seedDemoAccounts(): Promise<void> {
      seedDemoAccounts()
    },
    async authenticateDemo(email: string, password: string): Promise<AuthUserPayload | null> {
      return authenticateDemo(email, password)
    },
    async createSession(
      userId: string,
      opts?: { idTokenHint?: string | null; userAgent?: string | null; ip?: string | null; amr?: string[] | null },
    ): Promise<string> {
      return createSession(userId, opts)
    },
    async touchLastLogin(userId: string): Promise<void> {
      touchLastLogin(userId)
    },
    async getSessionUser(token: string): Promise<AuthUserPayload | null> {
      return getSessionUser(token)
    },
    async deleteSession(token: string): Promise<void> {
      deleteSession(token)
    },
    async cleanExpiredSessions(): Promise<void> {
      cleanExpiredSessions()
    },
    async listDemoAccounts(): Promise<Array<{ email: string; name: string; role: string }>> {
      return getDb()
        .prepare("SELECT email, name, role FROM users WHERE provider = 'demo' ORDER BY role, name")
        .all() as Array<{ email: string; name: string; role: string }>
    },

    // ── identity federation (TODO.federation/10) ──
    async findUserByEmail(email: string): Promise<AuthUserPayload | null> {
      return findUserByEmail(email)
    },
    async getUserById(id: string): Promise<AuthUserPayload | null> {
      return getUserById(id)
    },
    async findUserByProvider(provider: string, providerAccountId: string): Promise<AuthUserPayload | null> {
      return findUserByProvider(provider, providerAccountId)
    },
    async provisionSsoUser(input: {
      email: string
      name: string
      provider: string
      providerAccountId: string
      role: string
      orgId: string | null
    }): Promise<AuthUserPayload> {
      return provisionSsoUser(input)
    },
    async updateUserRoleOrg(userId: string, role: string, orgId: string | null): Promise<void> {
      updateUserRoleOrg(userId, role, orgId)
    },
    // ── the SSO sign-in state jar (TODO.identity/04) ──
    // ── federation peers (TODO.federation/04) ──
    // ── user administration (TODO.federation/12) ──
    async listUsers(): Promise<UserAdminRow[]> {
      return listUsers()
    },
    async createLocalUser(input: {
      email: string
      name: string
      role: string
      roles?: string[]
      orgId?: string | null
    }): Promise<UserAdminRow> {
      return createLocalUser(input)
    },
    async setUserRoles(id: string, role: string, roles: string[]): Promise<boolean> {
      return setUserRoles(id, role, roles)
    },
    async setUserActive(id: string, active: boolean): Promise<boolean> {
      return setUserActive(id, active)
    },

    // ── organization administration (TODO.identity/10) ──
    async createOrgJoinRequest(input: {
      name: string
      email: string
      orgId: string | null
      orgNameText: string | null
      requestedRole: string
      note?: string | null
    }): Promise<OrgJoinRequest> {
      return createOrgJoinRequest(input)
    },
    async getOrgJoinRequest(id: string): Promise<OrgJoinRequest | null> {
      return getOrgJoinRequest(id)
    },
    async listOrgJoinRequests(filter?: {
      scope?: 'org' | 'unregistered' | 'all'
      orgId?: string
      status?: OrgJoinRequest['status']
    }): Promise<OrgJoinRequest[]> {
      return listOrgJoinRequests(filter)
    },
    async decideOrgJoinRequest(
      id: string,
      decision: {
        status: 'approved' | 'refused'
        decidedBy: string
        refusalReason?: string | null
        invitedUserId?: string | null
      },
    ): Promise<OrgJoinRequest | null> {
      return decideOrgJoinRequest(id, decision)
    },
    async findPendingOrgJoinRequestByEmail(email: string): Promise<OrgJoinRequest | null> {
      return findPendingOrgJoinRequestByEmail(email)
    },

    // ── organization memberships (TODO.identity/11) ──
    async listOrgMemberships(userId: string): Promise<OrgMembership[]> {
      return listOrgMemberships(userId)
    },
    async listOrgMembers(orgId: string): Promise<OrgMembership[]> {
      return listOrgMembers(orgId)
    },
    async listAllOrgMemberships(): Promise<OrgMembership[]> {
      return listAllOrgMemberships()
    },
    async getOrgMembership(userId: string, orgId: string): Promise<OrgMembership | null> {
      return getOrgMembership(userId, orgId)
    },
    async createOrgMembership(input: {
      userId: string
      orgId: string
      roles: string[]
      state: OrgMembershipState
      invitedBy?: string | null
    }): Promise<OrgMembership | null> {
      return createOrgMembership(input)
    },
    async setOrgMembershipRoles(userId: string, orgId: string, roles: string[]): Promise<boolean> {
      return setOrgMembershipRoles(userId, orgId, roles)
    },
    async setOrgMembershipState(
      userId: string,
      orgId: string,
      state: OrgMembershipState,
      actor?: string | null,
    ): Promise<OrgMembership | null> {
      return setOrgMembershipState(userId, orgId, state, actor)
    },
    async setOrgMembershipCone(userId: string, orgId: string, cone: string | null): Promise<OrgMembership | null> {
      return setOrgMembershipCone(userId, orgId, cone)
    },
    async deleteOrgMembership(userId: string, orgId: string): Promise<boolean> {
      return deleteOrgMembership(userId, orgId)
    },
    async getSessionActiveOrg(token: string): Promise<string | null> {
      return getSessionActiveOrg(token)
    },
    async setSessionActiveOrg(token: string, orgId: string | null): Promise<boolean> {
      return setSessionActiveOrg(token, orgId)
    },

    // ── the organization registry (TODO.identity-features/05) ──
    async listOrgRegistryOrgs(): Promise<OrgRegistryOrg[]> {
      return listOrgRegistryOrgs()
    },
    async getOrgRegistryOrg(id: string): Promise<OrgRegistryOrg | null> {
      return getOrgRegistryOrg(id)
    },
    async createOrgRegistryOrg(input: {
      id: string
      name: string
      shortName?: string | null
      kind?: string | null
      country?: string | null
      contacts?: OrgRegistryContact[]
      participantRef?: string | null
      createdBy?: string | null
    }): Promise<OrgRegistryOrg | null> {
      return createOrgRegistryOrg(input)
    },
    async updateOrgRegistryOrg(
      id: string,
      patch: {
        name?: string
        shortName?: string | null
        kind?: string | null
        country?: string | null
        contacts?: OrgRegistryContact[]
        participantRef?: string | null
      },
      actor?: string | null,
    ): Promise<OrgRegistryOrg | null> {
      return updateOrgRegistryOrg(id, patch, actor)
    },
    async setOrgRegistryOrgState(id: string, state: OrgRegistryState, actor?: string | null): Promise<OrgRegistryOrg | null> {
      return setOrgRegistryOrgState(id, state, actor)
    },
    async deleteOrgRegistryOrg(id: string): Promise<boolean> {
      return deleteOrgRegistryOrg(id)
    },

    // ── the register's holder-org attribution (TODO.register/02) ──
    // ── the instrument register (TODO.register/03) ──
    // ── the OIDC Provider (TODO.identity/01) ──
    async getOidcClient(clientId: string): Promise<OidcClient | null> {
      return getOidcClient(clientId)
    },
    async listOidcClients(): Promise<OidcClient[]> {
      return listOidcClients()
    },
    async upsertOidcClient(input: {
      clientId: string
      name: string
      secretHash: string | null
      redirectUris: string[]
      claimsPolicy: { claims: string[] } | null
      createdBy?: string | null
    }): Promise<OidcClient> {
      return upsertOidcClient(input)
    },
    async setOidcClientStatus(clientId: string, status: OidcClient['status']): Promise<OidcClient | null> {
      return setOidcClientStatus(clientId, status)
    },
    async setOidcClientLaunch(clientId: string, launch: OidcClientLaunch | null): Promise<OidcClient | null> {
      return setOidcClientLaunch(clientId, launch)
    },
    async createOidcAuthorization(input: {
      id: string
      clientId: string
      redirectUri: string
      scope: string
      state: string
      nonce: string | null
      codeChallenge: string
      userId: string | null
      ttlMs: number
    }): Promise<OidcAuthorization> {
      return createOidcAuthorization(input)
    },
    async getOidcAuthorization(id: string): Promise<OidcAuthorization | null> {
      return getOidcAuthorization(id)
    },
    async decideOidcAuthorization(
      id: string,
      decision: { userId: string; decision: 'allow' | 'deny' },
    ): Promise<OidcAuthorization | null> {
      return decideOidcAuthorization(id, decision)
    },
    async createOidcCode(input: {
      code: string
      clientId: string
      redirectUri: string
      scope: string
      nonce: string | null
      codeChallenge: string
      userId: string
      contextOrg?: string | null
      amr?: string[] | null
      ttlMs: number
    }): Promise<void> {
      createOidcCode(input)
    },
    async consumeOidcCode(code: string): Promise<OidcCode | null> {
      return consumeOidcCode(code)
    },
    async createOidcAccessToken(input: {
      token: string
      userId: string
      clientId: string
      scope: string
      contextOrg?: string | null
      amr?: string[] | null
      ttlMs: number
    }): Promise<void> {
      createOidcAccessToken(input)
    },
    async getOidcAccessToken(token: string): Promise<OidcAccessToken | null> {
      return getOidcAccessToken(token)
    },
    async deleteOidcAccessToken(token: string, clientId: string): Promise<boolean> {
      return deleteOidcAccessToken(token, clientId)
    },
    async countOidcAccessTokensForClient(clientId: string): Promise<number> {
      return countOidcAccessTokensForClient(clientId)
    },
    async createOidcRefreshToken(input: {
      token: string
      userId: string
      clientId: string
      scope: string
      contextOrg?: string | null
      amr?: string[] | null
      authTime?: string | null
      familyId: string
      ttlMs: number
    }): Promise<OidcRefreshToken> {
      return createOidcRefreshToken(input)
    },
    async consumeOidcRefreshToken(token: string): Promise<ConsumeOidcRefreshTokenResult> {
      return consumeOidcRefreshToken(token)
    },
    async revokeOidcRefreshToken(token: string, clientId: string): Promise<boolean> {
      return revokeOidcRefreshToken(token, clientId)
    },
    async deleteOidcRefreshTokensForUserClient(userId: string, clientId: string): Promise<number> {
      return deleteOidcRefreshTokensForUserClient(userId, clientId)
    },
    async countOidcRefreshTokensForClient(clientId: string): Promise<number> {
      return countOidcRefreshTokensForClient(clientId)
    },
    async listOidcKeys(): Promise<OidcKeyRow[]> {
      return listOidcKeys()
    },
    async upsertOidcKey(input: { kid: string; publicJwk: string }): Promise<void> {
      upsertOidcKey(input)
    },
    // ── the remembered consent grants (TODO.identity-features/12) ──
    async getConsentGrant(userId: string, clientId: string, scope: string): Promise<OidcConsentGrant | null> {
      return getConsentGrant(userId, clientId, scope)
    },
    async recordConsentGrant(input: { userId: string; clientId: string; scope: string }): Promise<OidcConsentGrant> {
      return recordConsentGrant(input)
    },
    async listConsentGrants(userId: string): Promise<OidcConsentGrant[]> {
      return listConsentGrants(userId)
    },
    async revokeConsentGrant(id: string, userId: string): Promise<boolean> {
      return revokeConsentGrant(id, userId)
    },
    async listOidcConsentGrantsForClient(clientId: string): Promise<OidcConsentGrant[]> {
      return listOidcConsentGrantsForClient(clientId)
    },

    // ── the upstream providers (TODO.identity/08) ──
    async listIdentityProviders(): Promise<IdentityProvider[]> {
      return listIdentityProviders()
    },
    async getIdentityProvider(id: string): Promise<IdentityProvider | null> {
      return getIdentityProvider(id)
    },
    async upsertIdentityProvider(input: {
      id: string
      kind: IdentityProvider['kind']
      displayName: string
      brandMark?: string | null
      issuer?: string | null
      clientId: string
      clientSecretRef?: string | null
      scopes?: string | null
      enabled?: boolean
      createdBy?: string | null
    }): Promise<IdentityProvider> {
      return upsertIdentityProvider(input)
    },
    async setIdentityProviderEnabled(id: string, enabled: boolean): Promise<IdentityProvider | null> {
      return setIdentityProviderEnabled(id, enabled)
    },
    async deleteIdentityProvider(id: string): Promise<boolean> {
      return deleteIdentityProvider(id)
    },

    // ── the linked identities (TODO.identity/02's shape, 08's flows) ──
    async listIdentityLinks(userId: string): Promise<IdentityLink[]> {
      return listIdentityLinks(userId)
    },
    async listIdentityLinksBulk(userIds: string[]): Promise<Map<string, IdentityLink[]>> {
      return listIdentityLinksBulk(userIds)
    },
    async findIdentityLink(provider: string, providerAccountId: string): Promise<IdentityLink | null> {
      return findIdentityLink(provider, providerAccountId)
    },
    async createIdentityLink(input: {
      userId: string
      provider: string
      providerAccountId: string
      linkedBy?: string | null
    }): Promise<IdentityLink | null> {
      return createIdentityLink(input)
    },
    async deleteIdentityLink(userId: string, provider: string): Promise<boolean> {
      return deleteIdentityLink(userId, provider)
    },

    // ── the OP's account model (TODO.identity/02) ──
    async createOpAccount(input: {
      email: string
      name: string
      role: string
      createdBy?: string | null
    }): Promise<UserAdminRow | null> {
      return createOpAccount(input)
    },
    async getPasswordLogin(email: string): Promise<{ userId: string; hash: string; active: boolean } | null> {
      return getPasswordLogin(email)
    },
    async setPasswordHash(userId: string, hash: string, setBy?: string | null): Promise<void> {
      setPasswordHash(userId, hash, setBy)
    },
    async countSignInMethods(userId: string): Promise<{ password: boolean; links: number; passkeys: number }> {
      return countSignInMethods(userId)
    },
    async countSignInMethodsBulk(userIds: string[]): Promise<Map<string, { password: boolean; links: number; passkeys: number }>> {
      return countSignInMethodsBulk(userIds)
    },
    async createEnrollmentToken(input: {
      token: string
      userId: string
      createdBy?: string | null
      ttlMs: number
    }): Promise<EnrollmentToken> {
      return createEnrollmentToken(input)
    },
    async getEnrollmentToken(token: string): Promise<EnrollmentToken | null> {
      return getEnrollmentToken(token)
    },
    async completeEnrollment(token: string, passwordHash: string, setBy?: string | null): Promise<CompleteEnrollmentResult> {
      return completeEnrollment(token, passwordHash, setBy)
    },
    async listUserSessions(userId: string, currentToken?: string): Promise<SessionView[]> {
      return listUserSessions(userId, currentToken)
    },
    async deleteSessionById(userId: string, sessionId: string): Promise<boolean> {
      return deleteSessionById(userId, sessionId)
    },
    async listOpLiveSessions(currentToken?: string): Promise<OpLiveSession[]> {
      return listOpLiveSessions(currentToken)
    },
    async deleteAllUserSessions(userId: string): Promise<number> {
      return deleteAllUserSessions(userId)
    },
    // ── the account console (TODO.identity/06) ──
    async updateUserName(userId: string, name: string): Promise<boolean> {
      return updateUserName(userId, name)
    },
    async setUserAvatar(userId: string, avatarUrl: string | null): Promise<boolean> {
      return setUserAvatar(userId, avatarUrl)
    },
    async deletePasswordHash(userId: string): Promise<boolean> {
      return deletePasswordHash(userId)
    },
    async deleteOtherSessions(userId: string, keepToken: string): Promise<number> {
      return deleteOtherSessions(userId, keepToken)
    },
    async createEmailChangeToken(input: {
      token: string
      userId: string
      newEmail: string
      deliveredBy: 'mailer' | 'shown'
      kind?: 'change' | 'add' | 'verify'
      ttlMs: number
    }): Promise<EmailChangeToken> {
      return createEmailChangeToken(input)
    },
    async getEmailChangeToken(token: string): Promise<EmailChangeToken | null> {
      return getEmailChangeToken(token)
    },
    async getPendingEmailChange(userId: string): Promise<EmailChangeToken | null> {
      return getPendingEmailChange(userId)
    },
    async completeEmailChange(token: string): Promise<CompleteEmailChangeResult> {
      return completeEmailChange(token)
    },

    // ── multiple emails per account (TODO.identity-features/01) ──
    async listAccountEmails(userId: string): Promise<AccountEmail[]> {
      return listAccountEmails(userId)
    },
    async findUserByAnyEmail(email: string): Promise<AuthUserPayload | null> {
      return findUserByAnyEmail(email)
    },
    async addAccountEmail(userId: string, email: string, addedBy?: string | null): Promise<AddAccountEmailResult> {
      return addAccountEmail(userId, email, addedBy)
    },
    async markAccountEmailVerified(userId: string, email: string): Promise<boolean> {
      return markAccountEmailVerified(userId, email)
    },
    async setPrimaryAccountEmail(userId: string, email: string): Promise<'ok' | 'unknown' | 'unverified'> {
      return setPrimaryAccountEmail(userId, email)
    },
    async removeAccountEmail(userId: string, email: string): Promise<'ok' | 'primary' | 'unknown'> {
      return removeAccountEmail(userId, email)
    },

    // ── strong authentication: the factor registry (TODO.identity-sso/02 + /03) ──
    async createWebauthnChallenge(input: {
      challenge: string
      userId: string | null
      kind: WebauthnChallenge['kind']
      ttlMs: number
    }): Promise<void> {
      createWebauthnChallenge(input)
    },
    async consumeWebauthnChallenge(challenge: string): Promise<WebauthnChallenge | null> {
      return consumeWebauthnChallenge(challenge)
    },
    async createWebauthnCredential(input: {
      credentialId: string
      userId: string
      name: string
      publicKeyCose: string
      signCount: number
      aaguid: string | null
      transports: string[]
      ip?: string | null
    }): Promise<WebauthnCredential | null> {
      return createWebauthnCredential(input)
    },
    async listWebauthnCredentials(userId: string): Promise<WebauthnCredential[]> {
      return listWebauthnCredentials(userId)
    },
    async getWebauthnCredential(credentialId: string): Promise<WebauthnCredential | null> {
      return getWebauthnCredential(credentialId)
    },
    async deleteWebauthnCredential(userId: string, credentialId: string): Promise<boolean> {
      return deleteWebauthnCredential(userId, credentialId)
    },
    async advanceWebauthnCounter(credentialId: string, newCount: number, opts?: { ip?: string | null }): Promise<AdvanceCounterResult> {
      return advanceWebauthnCounter(credentialId, newCount, opts)
    },
    async createTotpSecret(input: { id: string; userId: string; name: string; secret: string }): Promise<TotpSecret> {
      return createTotpSecret(input)
    },
    async listTotpSecrets(userId: string): Promise<TotpSecret[]> {
      return listTotpSecrets(userId)
    },
    async getTotpSecret(id: string): Promise<TotpSecret | null> {
      return getTotpSecret(id)
    },
    async markTotpSecretVerified(id: string, userId: string, name: string): Promise<boolean> {
      return markTotpSecretVerified(id, userId, name)
    },
    async recordTotpEnrollFailure(id: string, userId: string): Promise<number> {
      return recordTotpEnrollFailure(id, userId)
    },
    async markTotpSecretUsed(id: string, opts?: { ip?: string | null }): Promise<void> {
      markTotpSecretUsed(id, opts)
    },
    async deleteTotpSecret(userId: string, id: string): Promise<boolean> {
      return deleteTotpSecret(userId, id)
    },
    async replaceRecoveryCodes(userId: string, batch: string, codeHashes: string[]): Promise<void> {
      replaceRecoveryCodes(userId, batch, codeHashes)
    },
    async recoveryCodeState(userId: string): Promise<RecoveryCodeState> {
      return recoveryCodeState(userId)
    },
    async consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean> {
      return consumeRecoveryCode(userId, codeHash)
    },
    async createMfaPending(input: { token: string; userId: string; amr: string[]; ttlMs: number }): Promise<void> {
      createMfaPending(input)
    },
    async getMfaPending(token: string): Promise<MfaPending | null> {
      return getMfaPending(token)
    },
    async consumeMfaPending(token: string): Promise<MfaPending | null> {
      return consumeMfaPending(token)
    },
    async recordMfaPendingFailure(token: string): Promise<MfaPending | null> {
      return recordMfaPendingFailure(token)
    },

    // ── the personal access tokens (TODO.identity-features/08) ──
    async createPersonalAccessToken(input: {
      id: string
      userId: string
      name: string
      tokenHash: string
      tokenPrefix: string
      scopes: string[]
      orgContext: string | null
      expiresAt: string
    }): Promise<PersonalAccessToken> {
      return createPersonalAccessToken(input)
    },
    async listPersonalAccessTokens(userId: string): Promise<PersonalAccessToken[]> {
      return listPersonalAccessTokens(userId)
    },
    async listOrgPersonalAccessTokens(orgId: string): Promise<PersonalAccessToken[]> {
      return listOrgPersonalAccessTokens(orgId)
    },
    async getPersonalAccessToken(id: string): Promise<PersonalAccessToken | null> {
      return getPersonalAccessToken(id)
    },
    async findPersonalAccessTokenByHash(tokenHash: string): Promise<PersonalAccessToken | null> {
      return findPersonalAccessTokenByHash(tokenHash)
    },
    async revokePersonalAccessToken(id: string, userId: string, revokedBy: string): Promise<boolean> {
      return revokePersonalAccessToken(id, userId, revokedBy)
    },
    async stampPersonalAccessTokenUse(
      id: string,
      stamps: { usedAt: string; auditAt?: string | null; expiryNotifiedAt?: string | null },
    ): Promise<void> {
      stampPersonalAccessTokenUse(id, stamps)
    },

    // ── the central user registry (TODO.identity/03) ──
    async listOpClientRoles(userId: string): Promise<OpClientRoleAssignment[]> {
      return listOpClientRoles(userId)
    },
    async listAllOpClientRoles(): Promise<OpClientRoleAssignment[]> {
      return listAllOpClientRoles()
    },
    async getOpClientRoles(userId: string, clientId: string): Promise<string[] | null> {
      return getOpClientRoles(userId, clientId)
    },
    async setOpClientRoles(userId: string, clientId: string, roles: string[], assignedBy: string | null): Promise<void> {
      setOpClientRoles(userId, clientId, roles, assignedBy)
    },
    async deleteOpClientRoles(userId: string, clientId: string): Promise<boolean> {
      return deleteOpClientRoles(userId, clientId)
    },
    async revokeOpUserCredentials(userId: string): Promise<{ sessions: number; accessTokens: number; refreshTokens: number; codes: number; authorizations: number }> {
      return revokeOpUserCredentials(userId)
    },
    async eraseOpAccount(userId: string): Promise<OpAccountErasure | null> {
      return eraseOpAccount(userId)
    },
    async updateOpAccount(id: string, input: { name?: string; email?: string }): Promise<boolean> {
      return updateOpAccount(id, input)
    },
    async lastAccountSignIns(): Promise<Record<string, string>> {
      return lastAccountSignIns()
    },

    // ── the workflow entity store + change journal ──
    async listEntities(store: string, options?: EntityListOptions): Promise<EntityRow[]> {
      return listEntities(store, options)
    },
    async getEntity(store: string, id: string): Promise<EntityRow | undefined> {
      return getEntity(store, id)
    },
    async putEntity(store: string, id: string, orgId: string | null, data: string): Promise<void> {
      putEntity(store, id, orgId, data)
    },
    async deleteEntity(store: string, id: string): Promise<boolean> {
      return deleteEntity(store, id)
    },
    // ── the platform event store (TODO.notify/01) ──
    // ── the notification subscriptions store (TODO.notify/02) ──
    // ── the inbox state (TODO.notify/03) ──
    // ── the email channel's delivery store (TODO.notify/04) ──
    // ── provisioning / dev support ──
  }
}

/** The node composition root's one-liner: the SQLite store becomes THE
 *  store (server/index.ts, the node scripts, the route-level tests). */
export function installSqliteStore(): ServerStore {
  const store = createSqliteServerStore()
  installStore(store)
  return store
}

// ── The extraction surface (TODO.identity-extract/01) ───────────────
// This subpath IS the SQLite cone (the map, PROGRESS/41 §2.1): the six
// pre-extraction modules (the composer above + store/entities/
// op-store/op-accounts-store/upstream-store under ./sqlite/) behind one
// specifier, so the cone's direct consumers (the dev-reset seam's
// getDb, the evidence adapter, the SQLite repository, the route-level
// tests) import unchanged names from the package.
export * from './sqlite/store'
export * from './sqlite/entities'
export * from './sqlite/op-store'
export * from './sqlite/op-accounts-store'
export * from './sqlite/factors-store'
export * from './sqlite/upstream-store'

/** The SQLite store's own DDL, shipped with the package. Consumers that
 *  replay the schema (reset-db, the tripwires) read it from this path
 *  instead of guessing the package's installed location. */
export const SQLITE_SCHEMA_PATH = fileURLToPath(new URL('./sqlite/schema.sql', import.meta.url))

/** The canonical D1 migration set, shipped with the package
 *  (migrations/): the ONE set both deployments apply. Wrangler's
 *  migrations_dir points at this directory in the consumer's
 *  node_modules, and the deploys' D1 journals key the bookkeeping on
 *  the FILENAMES. Expand-only, never renumber (AGENTS.md, the
 *  migration contract). The migrations test pins this set's end state
 *  to schema.sql in lockstep. */
export const MIGRATIONS_DIR = fileURLToPath(new URL('../../migrations', import.meta.url))
