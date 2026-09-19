// ═══════════════════════════════════════════════════════════════════
// The webhook event vocabulary (TODO.modern/08) — the SSOT whitelist.
// The names are the AUDIT JOURNAL's action names VERBATIM (never a
// translation layer — the journal is the event truth, the whitelist
// declares which acts carry delivery). Adding a deliverable act = one
// string here + one emission at the act's site (the OCP extension).
// ═══════════════════════════════════════════════════════════════════

export const WEBHOOK_EVENTS: readonly string[] = [
  'account.password',
  'account.session_revoked',
  'account.pat_minted',
  'account.pat_revoked',
  'factor.totp_enrolled',
  'factor.passkey_enrolled',
]

export function isWebhookEvent(name: string): boolean {
  return WEBHOOK_EVENTS.includes(name)
}

/** The delivery envelope: the envelope id, the journal action name, the
 *  owning account, the instant, and the journal row's metadata
 *  projection verbatim (the no-secrets projection the act itself
 *  chose — the delivery layer never widens it). */
export interface WebhookEnvelope {
  id: string
  event: string
  account: string
  created: string
  data: Record<string, unknown>
}

export function buildWebhookEnvelope(event: string, accountId: string, data: Record<string, unknown>): WebhookEnvelope {
  return {
    id: crypto.randomUUID(),
    event,
    account: accountId,
    created: new Date().toISOString(),
    data,
  }
}
