// ═══════════════════════════════════════════════════════════════════
// The remembered consent grants (TODO.identity-features/12) — the OP
// remembers the account holder's "Allow" per (user, client, scope set),
// so a repeat authorization the grant COVERS skips the consent page.
// The state is the kernel's (the oidc_consent_grants table, migration
// 0021; the ServerStore seam's getConsentGrant / recordConsentGrant /
// listConsentGrants / revokeConsentGrant); this module carries the OP
// half's pure projections + the audit helper the two routes share.
//
// The rules (the OIDC-correct behavior):
//   - the skip: /op/authorize answers the code directly when a live
//     grant covers the request's scope set AND the request carries no
//     prompt=consent (the OIDC re-consent signal always shows the page);
//   - the remember: the consent decision's allow records/refreshes the
//     grant (the store's upsert per user+client+scope);
//   - the revoke: the account console's "Revoke access" flips the live
//     row — the next sign-in re-prompts;
//   - the audit chain carries the grant + the revoke on the ACCOUNT's
//     own feed (entity_type 'account', the auditPat posture).
//
// WORKER-SAFE: the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { getStore, normalizeOidcScopeSet, type OidcConsentGrant } from '@oimlsmart/platform-server/store'

/** The grant acts' audit trail (the account's own activity feed shows
 *  them — the same discipline as auth/op/tokens.ts's auditPat: the audit
 *  never blocks the path). */
export async function auditGrant(
  action: string,
  entityId: string,
  actor: { userId?: string; userName?: string },
  metadata: Record<string, unknown>,
): Promise<void> {
  try {
    const id = crypto.randomUUID()
    await getStore().putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'account',
      entity_id: entityId,
      action,
      user_id: actor.userId,
      user_name: actor.userName,
      metadata,
    }))
  } catch (err) {
    console.error(`[op] consent-grant audit event ${action} failed to persist:`, (err as Error).message)
  }
}

/** The console's row: the grant projected for the account page's "apps
 *  they can access" section — the client's display name resolved from
 *  the registry (a client the registry since lost reads honestly by
 *  id), the scopes as a set, the remembered-at stamp. NEVER more. */
export interface ConsentGrantRow {
  id: string
  clientId: string
  clientName: string
  scopes: string[]
  createdAt: string
}

export async function consentGrantRow(store: ReturnType<typeof getStore>, grant: OidcConsentGrant): Promise<ConsentGrantRow> {
  const client = await store.getOidcClient(grant.clientId)
  return {
    id: grant.id,
    clientId: grant.clientId,
    clientName: client?.name ?? grant.clientId,
    scopes: normalizeOidcScopeSet(grant.scope).split(' ').filter(Boolean),
    createdAt: grant.createdAt,
  }
}
