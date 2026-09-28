// ═══════════════════════════════════════════════════════════════════
// The Ommisa member tier's self-enrollment policy core (the
// PROMPT.self-registration.md flow, rev 4): the eligibility judgments
// and the verified provisioning, worker-safe and store-injected.
//
// THE FLOW (the owner's law: NO STATE BEFORE THE MAILBOX IS PROVEN):
//   start    — the eligibility reads (the kill switch, the pickers, the
//              domain resolve, the dup-email read) and the upstream
//              attribution bounce. NOTHING is written.
//   callback — the attribution upstream's return (a fresh interactive
//              Google/GitHub login proves an attributable human): the
//              eligibility re-runs FRESH, the verification email goes
//              out. The link is SELF-CONTAINED (a time-bound HMAC token
//              bound to the receiving address) — still nothing written.
//   click    — the link's signature, expiry, and the fresh resolveOrg
//              verdict: only now the account is created
//              verified-by-construction, with the registry hit's roles
//              as the Ommisa client's per-client assignments (how
//              CIML-member standing reaches the service) and the org
//              binding the configuration names. The setup (the name +
//              the password) completes the enrollment.
//
// A replayed link finds the dup email and answers the honest
// already-registered sentence — the account's own existence is the
// one-time marker, no token rows anywhere.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '../../store'
import { loadDomains, resolveOrg, type DomainOwner } from './member-domains'

export interface SelfRegisterConfig {
  enabled: boolean
  /** The fail-closed reason when the deployment has not configured the
   *  tier (the org binding is the owner's deliberate act — the endpoint
   *  refuses rather than guess). */
  reason?: 'disabled' | 'not-configured'
  orgId: string
  client: string
  role: string
}

export function resolveSelfRegisterConfig(env: Record<string, string | undefined>): SelfRegisterConfig {
  const flag = env.OP_SELF_REGISTER?.trim()
  if (flag === '0' || flag === 'false') {
    return { enabled: false, reason: 'disabled', orgId: '', client: 'oiml-ommisa', role: 'user' }
  }
  const orgId = env.OP_SELF_REGISTER_ORG?.trim() ?? ''
  if (!orgId) {
    // Fail-closed: the tier's org binding is a deployment decision; an
    // unconfigured deployment refuses honestly instead of guessing.
    return { enabled: false, reason: 'not-configured', orgId: '', client: 'oiml-ommisa', role: 'user' }
  }
  return {
    enabled: true,
    orgId,
    client: env.OP_SELF_REGISTER_CLIENT?.trim() || 'oiml-ommisa',
    role: env.OP_SELF_REGISTER_ROLES?.trim() || 'user',
  }
}

export interface EligibilityVerdict {
  ok: boolean
  /** The queue fallback: the picked org declares admin_queue (the
   *  secretariat has not reviewed it) — the join-request queue is the
   *  path, never self-provisioning. */
  queue?: boolean
  /** The domain resolved to a DIFFERENT organization — the error names
   *  it (the pick-again sentence). */
  mismatch?: { country: string; org: string }
  error?: string
  hit?: DomainOwner
}

/** The eligibility judgment: the pickers (the country, then the org
 *  inside it) and the email's domain must all agree, under the
 *  registry's own dot-boundary matcher. Reads only — nothing writes. */
export function eligibilityFor(
  { country, org, email }: { country: string; org: string; email: string },
): EligibilityVerdict {
  const catalog = loadDomains()
  const pickedCountry = catalog.countries.find(c => c.country === country)
  if (!pickedCountry) {
    return { ok: false, error: 'the country you picked is not in the member-domains registry — pick your country from the list' }
  }
  const pickedOrg = pickedCountry.orgs.find(o => o.name === org)
  if (!pickedOrg) {
    return { ok: false, error: `the organization you picked does not belong to ${country} — pick your organization from ${country}'s list` }
  }
  const hit = resolveOrg(email)
  if (!hit) {
    return {
      ok: false,
      error: 'this email domain is not in the member-domains registry — if your organization should be eligible, an administrator can review your request through the join queue',
      queue: true,
    }
  }
  if (hit.org !== pickedOrg.name) {
    return {
      ok: false,
      mismatch: { country: hit.country, org: hit.org },
      error: `this domain is registered to ${hit.org} (${hit.country}) — choose it from the organization list`,
    }
  }
  if (pickedOrg.admin_queue) {
    return {
      ok: false,
      queue: true,
      error: 'your organization is enrolled through administrator review — submit the request and an administrator will review it',
    }
  }
  return { ok: true, hit }
}

/** The completion's input contract — the name and the password arrive
 *  at the verified click's setup step (never before: nothing about the
 *  account is stored until the mailbox is proven). */
export interface CompletionInput {
  name: string
  password: string
}
