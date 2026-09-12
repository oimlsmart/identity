// ═══════════════════════════════════════════════════════════════════
// The SQLite ServerStore (TODO.cs-e2e/14): the node/self-hosted half
// of the backend seam — the SAME sync modules the server always used
// (store.ts + entities.ts, better-sqlite3) exposed through the async
// ServerStore contract the routes consume. Zero behavior change: every
// method delegates one-for-one.
//
// INSTANCE-SHAPED since TODO.restructure/28-D (the D1 class mirrored):
// SqliteServerStore below holds its database handle as instance state;
// createSqliteStore(path) answers a store over a database the caller
// names — two instances in one process is the federation spec's
// standing proof. installSqliteStore() (the composition root's
// one-liner) stays the DEFAULT-instance shim: no caller changed.
//
// NODE-ONLY: this module imports better-sqlite3 through store.ts. The
// Worker bundle never sees it (the worker entry installs the D1 store
// instead) — the audit the wrangler config documents.
// ═══════════════════════════════════════════════════════════════════

import { fileURLToPath } from 'url'
import type Database from 'better-sqlite3'
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
  openSqliteDatabase,
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

// TODO.restructure/28-D — the INSTANCE shape, mirroring the D1
// store's class (server/store/d1.ts): one class per open database, the
// handle held as instance state (this.db), no module state. The sync
// modules' verbs take the handle as their first parameter; every
// method below delegates one-for-one, byte-identical routing to before.
export class SqliteServerStore implements ServerStore {
  private readonly db: Database.Database

  constructor(db: Database.Database) {
    this.db = db
  }

  // ── users / sessions ──
  async seedDemoAccounts(): Promise<void> {
    seedDemoAccounts(this.db)
  }
  async authenticateDemo(email: string, password: string): Promise<AuthUserPayload | null> {
    return authenticateDemo(this.db, email, password)
  }
  async createSession(
    userId: string,
    opts?: { idTokenHint?: string | null; userAgent?: string | null; ip?: string | null; amr?: string[] | null },
  ): Promise<string> {
    return createSession(this.db, userId, opts)
  }
  async touchLastLogin(userId: string): Promise<void> {
    touchLastLogin(this.db, userId)
  }
  async getSessionUser(token: string): Promise<AuthUserPayload | null> {
    return getSessionUser(this.db, token)
  }
  async deleteSession(token: string): Promise<void> {
    deleteSession(this.db, token)
  }
  async cleanExpiredSessions(): Promise<void> {
    cleanExpiredSessions(this.db)
  }
  async listDemoAccounts(): Promise<Array<{ email: string; name: string; role: string }>> {
    return this.db
      .prepare("SELECT email, name, role FROM users WHERE provider = 'demo' ORDER BY role, name")
      .all() as Array<{ email: string; name: string; role: string }>
  }

  // ── identity federation (TODO.federation/10) ──
  async findUserByEmail(email: string): Promise<AuthUserPayload | null> {
    return findUserByEmail(this.db, email)
  }
  async getUserById(id: string): Promise<AuthUserPayload | null> {
    return getUserById(this.db, id)
  }
  async findUserByProvider(provider: string, providerAccountId: string): Promise<AuthUserPayload | null> {
    return findUserByProvider(this.db, provider, providerAccountId)
  }
  async provisionSsoUser(input: {
    email: string
    name: string
    provider: string
    providerAccountId: string
    role: string
    orgId: string | null
  }): Promise<AuthUserPayload> {
    return provisionSsoUser(this.db, input)
  }
  async updateUserRoleOrg(userId: string, role: string, orgId: string | null): Promise<void> {
    updateUserRoleOrg(this.db, userId, role, orgId)
  }
  // ── the SSO sign-in state jar (TODO.identity/04) ──
  // ── federation peers (TODO.federation/04) ──
  // ── user administration (TODO.federation/12) ──
  async listUsers(): Promise<UserAdminRow[]> {
    return listUsers(this.db)
  }
  async createLocalUser(input: {
    email: string
    name: string
    role: string
    roles?: string[]
    orgId?: string | null
  }): Promise<UserAdminRow> {
    return createLocalUser(this.db, input)
  }
  async setUserRoles(id: string, role: string, roles: string[]): Promise<boolean> {
    return setUserRoles(this.db, id, role, roles)
  }
  async setUserActive(id: string, active: boolean): Promise<boolean> {
    return setUserActive(this.db, id, active)
  }

  // ── organization administration (TODO.identity/10) ──
  async createOrgJoinRequest(input: {
    name: string
    email: string
    orgId: string | null
    orgNameText: string | null
    requestedRole: string
    note?: string | null
  }): Promise<OrgJoinRequest> {
    return createOrgJoinRequest(this.db, input)
  }
  async getOrgJoinRequest(id: string): Promise<OrgJoinRequest | null> {
    return getOrgJoinRequest(this.db, id)
  }
  async listOrgJoinRequests(filter?: {
    scope?: 'org' | 'unregistered' | 'all'
    orgId?: string
    status?: OrgJoinRequest['status']
  }): Promise<OrgJoinRequest[]> {
    return listOrgJoinRequests(this.db, filter)
  }
  async decideOrgJoinRequest(
    id: string,
    decision: {
      status: 'approved' | 'refused'
      decidedBy: string
      refusalReason?: string | null
      invitedUserId?: string | null
    }
  ): Promise<OrgJoinRequest | null> {
    return decideOrgJoinRequest(this.db, id, decision)
  }
  async findPendingOrgJoinRequestByEmail(email: string): Promise<OrgJoinRequest | null> {
    return findPendingOrgJoinRequestByEmail(this.db, email)
  }

  // ── organization memberships (TODO.identity/11) ──
  async listOrgMemberships(userId: string): Promise<OrgMembership[]> {
    return listOrgMemberships(this.db, userId)
  }
  async listOrgMembers(orgId: string): Promise<OrgMembership[]> {
    return listOrgMembers(this.db, orgId)
  }
  async listAllOrgMemberships(): Promise<OrgMembership[]> {
    return listAllOrgMemberships(this.db)
  }
  async getOrgMembership(userId: string, orgId: string): Promise<OrgMembership | null> {
    return getOrgMembership(this.db, userId, orgId)
  }
  async createOrgMembership(input: {
    userId: string
    orgId: string
    roles: string[]
    state: OrgMembershipState
    invitedBy?: string | null
  }): Promise<OrgMembership | null> {
    return createOrgMembership(this.db, input)
  }
  async setOrgMembershipRoles(userId: string, orgId: string, roles: string[]): Promise<boolean> {
    return setOrgMembershipRoles(this.db, userId, orgId, roles)
  }
  async setOrgMembershipState(
    userId: string,
    orgId: string,
    state: OrgMembershipState,
    actor?: string | null,
  ): Promise<OrgMembership | null> {
    return setOrgMembershipState(this.db, userId, orgId, state, actor)
  }
  async setOrgMembershipCone(userId: string, orgId: string, cone: string | null): Promise<OrgMembership | null> {
    return setOrgMembershipCone(this.db, userId, orgId, cone)
  }
  async deleteOrgMembership(userId: string, orgId: string): Promise<boolean> {
    return deleteOrgMembership(this.db, userId, orgId)
  }
  async getSessionActiveOrg(token: string): Promise<string | null> {
    return getSessionActiveOrg(this.db, token)
  }
  async setSessionActiveOrg(token: string, orgId: string | null): Promise<boolean> {
    return setSessionActiveOrg(this.db, token, orgId)
  }

  // ── the organization registry (TODO.identity-features/05) ──
  async listOrgRegistryOrgs(): Promise<OrgRegistryOrg[]> {
    return listOrgRegistryOrgs(this.db)
  }
  async getOrgRegistryOrg(id: string): Promise<OrgRegistryOrg | null> {
    return getOrgRegistryOrg(this.db, id)
  }
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
    return createOrgRegistryOrg(this.db, input)
  }
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
    return updateOrgRegistryOrg(this.db, id, patch, actor)
  }
  async setOrgRegistryOrgState(id: string, state: OrgRegistryState, actor?: string | null): Promise<OrgRegistryOrg | null> {
    return setOrgRegistryOrgState(this.db, id, state, actor)
  }
  async deleteOrgRegistryOrg(id: string): Promise<boolean> {
    return deleteOrgRegistryOrg(this.db, id)
  }

  // ── the register's holder-org attribution (TODO.register/02) ──
  // ── the instrument register (TODO.register/03) ──
  // ── the OIDC Provider (TODO.identity/01) ──
  async getOidcClient(clientId: string): Promise<OidcClient | null> {
    return getOidcClient(this.db, clientId)
  }
  async listOidcClients(): Promise<OidcClient[]> {
    return listOidcClients(this.db)
  }
  async upsertOidcClient(input: {
    clientId: string
    name: string
    secretHash: string | null
    redirectUris: string[]
    claimsPolicy: { claims: string[] } | null
    createdBy?: string | null
  }): Promise<OidcClient> {
    return upsertOidcClient(this.db, input)
  }
  async setOidcClientStatus(clientId: string, status: OidcClient['status']): Promise<OidcClient | null> {
    return setOidcClientStatus(this.db, clientId, status)
  }
  async setOidcClientLaunch(clientId: string, launch: OidcClientLaunch | null): Promise<OidcClient | null> {
    return setOidcClientLaunch(this.db, clientId, launch)
  }
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
    return createOidcAuthorization(this.db, input)
  }
  async getOidcAuthorization(id: string): Promise<OidcAuthorization | null> {
    return getOidcAuthorization(this.db, id)
  }
  async decideOidcAuthorization(
    id: string,
    decision: { userId: string; decision: 'allow' | 'deny' },
  ): Promise<OidcAuthorization | null> {
    return decideOidcAuthorization(this.db, id, decision)
  }
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
    createOidcCode(this.db, input)
  }
  async consumeOidcCode(code: string): Promise<OidcCode | null> {
    return consumeOidcCode(this.db, code)
  }
  async createOidcAccessToken(input: {
    token: string
    userId: string
    clientId: string
    scope: string
    contextOrg?: string | null
    amr?: string[] | null
    ttlMs: number
  }): Promise<void> {
    createOidcAccessToken(this.db, input)
  }
  async getOidcAccessToken(token: string): Promise<OidcAccessToken | null> {
    return getOidcAccessToken(this.db, token)
  }
  async deleteOidcAccessToken(token: string, clientId: string): Promise<boolean> {
    return deleteOidcAccessToken(this.db, token, clientId)
  }
  async countOidcAccessTokensForClient(clientId: string): Promise<number> {
    return countOidcAccessTokensForClient(this.db, clientId)
  }
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
    return createOidcRefreshToken(this.db, input)
  }
  async consumeOidcRefreshToken(token: string): Promise<ConsumeOidcRefreshTokenResult> {
    return consumeOidcRefreshToken(this.db, token)
  }
  async revokeOidcRefreshToken(token: string, clientId: string): Promise<boolean> {
    return revokeOidcRefreshToken(this.db, token, clientId)
  }
  async deleteOidcRefreshTokensForUserClient(userId: string, clientId: string): Promise<number> {
    return deleteOidcRefreshTokensForUserClient(this.db, userId, clientId)
  }
  async countOidcRefreshTokensForClient(clientId: string): Promise<number> {
    return countOidcRefreshTokensForClient(this.db, clientId)
  }
  async listOidcKeys(): Promise<OidcKeyRow[]> {
    return listOidcKeys(this.db)
  }
  async upsertOidcKey(input: { kid: string; publicJwk: string }): Promise<void> {
    upsertOidcKey(this.db, input)
  }
  // ── the remembered consent grants (TODO.identity-features/12) ──
  async getConsentGrant(userId: string, clientId: string, scope: string): Promise<OidcConsentGrant | null> {
    return getConsentGrant(this.db, userId, clientId, scope)
  }
  async recordConsentGrant(input: { userId: string; clientId: string; scope: string }): Promise<OidcConsentGrant> {
    return recordConsentGrant(this.db, input)
  }
  async listConsentGrants(userId: string): Promise<OidcConsentGrant[]> {
    return listConsentGrants(this.db, userId)
  }
  async revokeConsentGrant(id: string, userId: string): Promise<boolean> {
    return revokeConsentGrant(this.db, id, userId)
  }
  async listOidcConsentGrantsForClient(clientId: string): Promise<OidcConsentGrant[]> {
    return listOidcConsentGrantsForClient(this.db, clientId)
  }

  // ── the upstream providers (TODO.identity/08) ──
  async listIdentityProviders(): Promise<IdentityProvider[]> {
    return listIdentityProviders(this.db)
  }
  async getIdentityProvider(id: string): Promise<IdentityProvider | null> {
    return getIdentityProvider(this.db, id)
  }
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
    return upsertIdentityProvider(this.db, input)
  }
  async setIdentityProviderEnabled(id: string, enabled: boolean): Promise<IdentityProvider | null> {
    return setIdentityProviderEnabled(this.db, id, enabled)
  }
  async deleteIdentityProvider(id: string): Promise<boolean> {
    return deleteIdentityProvider(this.db, id)
  }

  // ── the linked identities (TODO.identity/02's shape, 08's flows) ──
  async listIdentityLinks(userId: string): Promise<IdentityLink[]> {
    return listIdentityLinks(this.db, userId)
  }
  async listIdentityLinksBulk(userIds: string[]): Promise<Map<string, IdentityLink[]>> {
    return listIdentityLinksBulk(this.db, userIds)
  }
  async findIdentityLink(provider: string, providerAccountId: string): Promise<IdentityLink | null> {
    return findIdentityLink(this.db, provider, providerAccountId)
  }
  async createIdentityLink(input: {
    userId: string
    provider: string
    providerAccountId: string
    linkedBy?: string | null
  }): Promise<IdentityLink | null> {
    return createIdentityLink(this.db, input)
  }
  async deleteIdentityLink(userId: string, provider: string): Promise<boolean> {
    return deleteIdentityLink(this.db, userId, provider)
  }

  // ── the OP's account model (TODO.identity/02) ──
  async createOpAccount(input: {
    email: string
    name: string
    role: string
    createdBy?: string | null
  }): Promise<UserAdminRow | null> {
    return createOpAccount(this.db, input)
  }
  async getPasswordLogin(email: string): Promise<{ userId: string; hash: string; active: boolean } | null> {
    return getPasswordLogin(this.db, email)
  }
  async setPasswordHash(userId: string, hash: string, setBy?: string | null): Promise<void> {
    setPasswordHash(this.db, userId, hash, setBy)
  }
  async countSignInMethods(userId: string): Promise<{ password: boolean; links: number; passkeys: number }> {
    return countSignInMethods(this.db, userId)
  }
  async countSignInMethodsBulk(userIds: string[]): Promise<Map<string, { password: boolean; links: number; passkeys: number }>> {
    return countSignInMethodsBulk(this.db, userIds)
  }
  async createEnrollmentToken(input: {
    token: string
    userId: string
    createdBy?: string | null
    ttlMs: number
  }): Promise<EnrollmentToken> {
    return createEnrollmentToken(this.db, input)
  }
  async getEnrollmentToken(token: string): Promise<EnrollmentToken | null> {
    return getEnrollmentToken(this.db, token)
  }
  async completeEnrollment(token: string, passwordHash: string, setBy?: string | null): Promise<CompleteEnrollmentResult> {
    return completeEnrollment(this.db, token, passwordHash, setBy)
  }
  async listUserSessions(userId: string, currentToken?: string): Promise<SessionView[]> {
    return listUserSessions(this.db, userId, currentToken)
  }
  async deleteSessionById(userId: string, sessionId: string): Promise<boolean> {
    return deleteSessionById(this.db, userId, sessionId)
  }
  async listOpLiveSessions(currentToken?: string): Promise<OpLiveSession[]> {
    return listOpLiveSessions(this.db, currentToken)
  }
  async deleteAllUserSessions(userId: string): Promise<number> {
    return deleteAllUserSessions(this.db, userId)
  }
  // ── the account console (TODO.identity/06) ──
  async updateUserName(userId: string, name: string): Promise<boolean> {
    return updateUserName(this.db, userId, name)
  }
  async setUserAvatar(userId: string, avatarUrl: string | null): Promise<boolean> {
    return setUserAvatar(this.db, userId, avatarUrl)
  }
  async deletePasswordHash(userId: string): Promise<boolean> {
    return deletePasswordHash(this.db, userId)
  }
  async deleteOtherSessions(userId: string, keepToken: string): Promise<number> {
    return deleteOtherSessions(this.db, userId, keepToken)
  }
  async createEmailChangeToken(input: {
    token: string
    userId: string
    newEmail: string
    deliveredBy: 'mailer' | 'shown'
    kind?: 'change' | 'add' | 'verify'
    ttlMs: number
  }): Promise<EmailChangeToken> {
    return createEmailChangeToken(this.db, input)
  }
  async getEmailChangeToken(token: string): Promise<EmailChangeToken | null> {
    return getEmailChangeToken(this.db, token)
  }
  async getPendingEmailChange(userId: string): Promise<EmailChangeToken | null> {
    return getPendingEmailChange(this.db, userId)
  }
  async completeEmailChange(token: string): Promise<CompleteEmailChangeResult> {
    return completeEmailChange(this.db, token)
  }

  // ── multiple emails per account (TODO.identity-features/01) ──
  async listAccountEmails(userId: string): Promise<AccountEmail[]> {
    return listAccountEmails(this.db, userId)
  }
  async findUserByAnyEmail(email: string): Promise<AuthUserPayload | null> {
    return findUserByAnyEmail(this.db, email)
  }
  async addAccountEmail(userId: string, email: string, addedBy?: string | null): Promise<AddAccountEmailResult> {
    return addAccountEmail(this.db, userId, email, addedBy)
  }
  async markAccountEmailVerified(userId: string, email: string): Promise<boolean> {
    return markAccountEmailVerified(this.db, userId, email)
  }
  async setPrimaryAccountEmail(userId: string, email: string): Promise<'ok' | 'unknown' | 'unverified'> {
    return setPrimaryAccountEmail(this.db, userId, email)
  }
  async removeAccountEmail(userId: string, email: string): Promise<'ok' | 'primary' | 'unknown'> {
    return removeAccountEmail(this.db, userId, email)
  }

  // ── strong authentication: the factor registry (TODO.identity-sso/02 + /03) ──
  async createWebauthnChallenge(input: {
    challenge: string
    userId: string | null
    kind: WebauthnChallenge['kind']
    ttlMs: number
  }): Promise<void> {
    createWebauthnChallenge(this.db, input)
  }
  async consumeWebauthnChallenge(challenge: string): Promise<WebauthnChallenge | null> {
    return consumeWebauthnChallenge(this.db, challenge)
  }
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
    return createWebauthnCredential(this.db, input)
  }
  async listWebauthnCredentials(userId: string): Promise<WebauthnCredential[]> {
    return listWebauthnCredentials(this.db, userId)
  }
  async getWebauthnCredential(credentialId: string): Promise<WebauthnCredential | null> {
    return getWebauthnCredential(this.db, credentialId)
  }
  async deleteWebauthnCredential(userId: string, credentialId: string): Promise<boolean> {
    return deleteWebauthnCredential(this.db, userId, credentialId)
  }
  async advanceWebauthnCounter(credentialId: string, newCount: number, opts?: { ip?: string | null }): Promise<AdvanceCounterResult> {
    return advanceWebauthnCounter(this.db, credentialId, newCount, opts)
  }
  async createTotpSecret(input: { id: string; userId: string; name: string; secret: string }): Promise<TotpSecret> {
    return createTotpSecret(this.db, input)
  }
  async listTotpSecrets(userId: string): Promise<TotpSecret[]> {
    return listTotpSecrets(this.db, userId)
  }
  async getTotpSecret(id: string): Promise<TotpSecret | null> {
    return getTotpSecret(this.db, id)
  }
  async markTotpSecretVerified(id: string, userId: string, name: string): Promise<boolean> {
    return markTotpSecretVerified(this.db, id, userId, name)
  }
  async recordTotpEnrollFailure(id: string, userId: string): Promise<number> {
    return recordTotpEnrollFailure(this.db, id, userId)
  }
  async markTotpSecretUsed(id: string, opts?: { ip?: string | null }): Promise<void> {
    markTotpSecretUsed(this.db, id, opts)
  }
  async deleteTotpSecret(userId: string, id: string): Promise<boolean> {
    return deleteTotpSecret(this.db, userId, id)
  }
  async replaceRecoveryCodes(userId: string, batch: string, codeHashes: string[]): Promise<void> {
    replaceRecoveryCodes(this.db, userId, batch, codeHashes)
  }
  async recoveryCodeState(userId: string): Promise<RecoveryCodeState> {
    return recoveryCodeState(this.db, userId)
  }
  async consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean> {
    return consumeRecoveryCode(this.db, userId, codeHash)
  }
  async createMfaPending(input: { token: string; userId: string; amr: string[]; ttlMs: number }): Promise<void> {
    createMfaPending(this.db, input)
  }
  async getMfaPending(token: string): Promise<MfaPending | null> {
    return getMfaPending(this.db, token)
  }
  async consumeMfaPending(token: string): Promise<MfaPending | null> {
    return consumeMfaPending(this.db, token)
  }
  async recordMfaPendingFailure(token: string): Promise<MfaPending | null> {
    return recordMfaPendingFailure(this.db, token)
  }

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
    return createPersonalAccessToken(this.db, input)
  }
  async listPersonalAccessTokens(userId: string): Promise<PersonalAccessToken[]> {
    return listPersonalAccessTokens(this.db, userId)
  }
  async listOrgPersonalAccessTokens(orgId: string): Promise<PersonalAccessToken[]> {
    return listOrgPersonalAccessTokens(this.db, orgId)
  }
  async getPersonalAccessToken(id: string): Promise<PersonalAccessToken | null> {
    return getPersonalAccessToken(this.db, id)
  }
  async findPersonalAccessTokenByHash(tokenHash: string): Promise<PersonalAccessToken | null> {
    return findPersonalAccessTokenByHash(this.db, tokenHash)
  }
  async revokePersonalAccessToken(id: string, userId: string, revokedBy: string): Promise<boolean> {
    return revokePersonalAccessToken(this.db, id, userId, revokedBy)
  }
  async stampPersonalAccessTokenUse(
    id: string,
    stamps: { usedAt: string; auditAt?: string | null; expiryNotifiedAt?: string | null },
  ): Promise<void> {
    stampPersonalAccessTokenUse(this.db, id, stamps)
  }

  // ── the central user registry (TODO.identity/03) ──
  async listOpClientRoles(userId: string): Promise<OpClientRoleAssignment[]> {
    return listOpClientRoles(this.db, userId)
  }
  async listAllOpClientRoles(): Promise<OpClientRoleAssignment[]> {
    return listAllOpClientRoles(this.db)
  }
  async getOpClientRoles(userId: string, clientId: string): Promise<string[] | null> {
    return getOpClientRoles(this.db, userId, clientId)
  }
  async setOpClientRoles(userId: string, clientId: string, roles: string[], assignedBy: string | null): Promise<void> {
    setOpClientRoles(this.db, userId, clientId, roles, assignedBy)
  }
  async deleteOpClientRoles(userId: string, clientId: string): Promise<boolean> {
    return deleteOpClientRoles(this.db, userId, clientId)
  }
  async revokeOpUserCredentials(userId: string): Promise<{ sessions: number; accessTokens: number; refreshTokens: number; codes: number; authorizations: number }> {
    return revokeOpUserCredentials(this.db, userId)
  }
  async eraseOpAccount(userId: string): Promise<OpAccountErasure | null> {
    return eraseOpAccount(this.db, userId)
  }
  async updateOpAccount(id: string, input: { name?: string; email?: string }): Promise<boolean> {
    return updateOpAccount(this.db, id, input)
  }
  async lastAccountSignIns(): Promise<Record<string, string>> {
    return lastAccountSignIns(this.db)
  }

  // ── the workflow entity store + change journal ──
  async listEntities(store: string, options?: EntityListOptions): Promise<EntityRow[]> {
    return listEntities(this.db, store, options)
  }
  async getEntity(store: string, id: string): Promise<EntityRow | undefined> {
    return getEntity(this.db, store, id)
  }
  async putEntity(store: string, id: string, orgId: string | null, data: string): Promise<void> {
    putEntity(this.db, store, id, orgId, data)
  }
  async deleteEntity(store: string, id: string): Promise<boolean> {
    return deleteEntity(this.db, store, id)
  }
  // ── the platform event store (TODO.notify/01) ──
  // ── the notification subscriptions store (TODO.notify/02) ──
  // ── the inbox state (TODO.notify/03) ──
  // ── the email channel's delivery store (TODO.notify/04) ──
  // ── provisioning / dev support ──
}

/** The INSTANCE factory (TODO.restructure/28-D): open the database at
 *  the path and answer the ServerStore bound to it — a second store in
 *  the same process, its own file, its own rows. The federation spec
 *  (id-whitelabel-federation.test.ts) runs its central OP on exactly
 *  this factory, in-process beside the default instance. */
export function createSqliteStore(path: string): SqliteServerStore {
  return new SqliteServerStore(openSqliteDatabase(path))
}

/** The DEFAULT instance's ServerStore: getDb's named handle (DATABASE_PATH
 *  or the pre-extraction home) — the historical no-arg composer, unchanged
 *  behavior, so every existing caller keeps working untouched. */
export function createSqliteServerStore(): SqliteServerStore {
  return new SqliteServerStore(getDb())
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
