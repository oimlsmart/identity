// ═══════════════════════════════════════════════════════════════════
// The OIDC client registry's bootstrap (TODO.identity/01) — the known
// instances seeded from the OP_CLIENT_SEED env (a JSON array), the same
// posture as the demo-account seed: idempotent upserts at boot, then the
// rows are ADMIN-MANAGED (the registry API in routes/op.ts; the full
// console UI is TODO.identity/03's).
//
// A seed entry:
//   {
//     "client_id": "oiml-smart-platform",
//     "name": "OIML SMART platform hub",
//     "secret": "…",                        // OPTIONAL — absent = a
//                                           // public client (PKCE only)
//     "redirect_uris": ["https://platform.oimlsmart.org/api/auth/callback/oidc"],
//     "claims_policy": { "claims": ["roles", "groups", "org"],
//                        "roles": ["admin", "cs_admin", "ia_officer"] }
//                                           // OPTIONAL — claims: the claims
//                                           // the ID token carries for THIS
//                                           // client (absent = profile +
//                                           // email only; role claims
//                                           // are a per-client privilege);
//                                           // roles (TODO.identity/03): the
//                                           // allowlist bounding WHICH roles
//                                           // those claims may carry (absent
//                                           // = unbounded by the policy).
//     "launch": { "url": "https://platform.oimlsmart.org/api/auth/signin/oidc",
//                 "icon": "grid", "description": "The certification hub",
//                 "visibility": "roles" }
//                                           // OPTIONAL (the SSO home) — the
//                                           // launcher's card; absent = the
//                                           // stored card stays the admin's
//                                           // (the upsert never touches it).
//   }
//
// THE DEVICE CLASS (the machine cone — auth/op/device-clients.ts): a
// non-human client registered PER DEVICE. The seed entry:
//   {
//     "client_id": "device-acme-lc500-0001",
//     "name": "ACME LC-500 sn 0001 (the twin)",
//     "class": "device",
//     "device": { "id": "acme-lc500-0001", "org": "mfr-acme",
//                 "instrument_model": "acme-lc500@2021" },
//     "secret": "…"                        // REQUIRED — a device client is
//                                          // confidential (client_credentials
//                                          // at /op/token; there is no PKCE
//                                          // leg to carry a public one)
//   }
// A device entry carries NO redirect_uris (nothing redirects), NO launch
// card (the SSO home is a human surface), and NO claims_policy (the class
// fixes the claim set: the device id, its org, its instrument model
// reference — never user claims).
//
// THE SERVICE CLASS (the machine cone's general half — auth/op/
// service-clients.ts, TODO.identity-ops/07): a non-human client
// registered PER SERVICE ACCOUNT (the agent pipelines / MCP servers
// beyond the device cone). The seed entry:
//   {
//     "client_id": "svc-rag-mcp-ingest",
//     "name": "The RAG's MCP ingest pipeline",
//     "class": "service",
//     "service": { "id": "rag-mcp-ingest", "org": "oimlsmart",
//                  "audience": "oiml-rag-mcp",
//                  "scopes": ["documents:read", "ingest:write"] },
//     "secret": "…"                        // REQUIRED — the machine
//                                          // classes are confidential
//                                          // (client_credentials at
//                                          // /op/token)
//   }
// A service entry carries NO redirect_uris, NO launch card, and NO
// claims_policy (the class fixes the claim set: the service id, its org,
// the declared audience, the narrowed scope allowlist — never user
// claims). The machine classes' rules are identical here; only the
// binding block differs.
//
// The plaintext seed secret is hashed (PBKDF2, secrets.ts) before it
// touches the database; the env itself rides a Worker secret when it
// carries secrets. A seeded client's UPDATE on re-seed keeps the row's
// status (a disabled client stays disabled — the seed never re-enables).
//
// WORKER-SAFE: no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '@oimlsmart/platform-server/store'
import { hashClientSecret } from './secrets'
import { validateLaunch, type LaunchInput } from './launch'
import { DEVICE_CLASS, validateDeviceBlock, type DeviceClientClaims, type OpClientPolicy } from './device-clients'
import { SERVICE_CLASS, validateServiceBlock, type OpServicePolicy, type ServiceClientClaims } from './service-clients'

type EnvLike = Record<string, string | undefined>

export interface OpClientSeedEntry {
  client_id: string
  name: string
  secret?: string
  /** The application class (absent `class`): the exact redirect URIs.
   *  The machine classes never carry them (nothing redirects) — absent
   *  or an empty list. */
  redirect_uris?: string[]
  claims_policy?: { claims: string[]; roles?: string[] }
  /** The SSO home's launch card (OPTIONAL — absent leaves the stored
   *  metadata to the admin's edits; the client may never join the
   *  launcher). The machine classes NEVER carry one. */
  launch?: LaunchInput
  /** The machine cone (auth/op/device-clients.ts + service-clients.ts):
   *  'device' registers a non-human, per-device client; 'service' a
   *  non-human, per-service-account client (both client_credentials
   *  only, always confidential). ABSENT = the application class. */
  class?: typeof DEVICE_CLASS | typeof SERVICE_CLASS
  /** The device identity the client binds (REQUIRED with class
   *  'device', refused otherwise). */
  device?: DeviceClientClaims
  /** The service identity the client binds (REQUIRED with class
   *  'service', refused otherwise). */
  service?: ServiceClientClaims
}

/** Parse + validate the seed declaration. Throws honestly on a malformed
 *  document — a misdeclared registry must fail the boot, never guess. */
export function parseOpClientSeed(raw: string): OpClientSeedEntry[] {
  const parsed = JSON.parse(raw) as unknown
  if (!Array.isArray(parsed)) throw new Error('OP_CLIENT_SEED must be a JSON array of client entries')
  return parsed.map((entry, i) => {
    const rec = entry as Record<string, unknown>
    if (typeof rec?.client_id !== 'string' || !rec.client_id) throw new Error(`OP_CLIENT_SEED[${i}]: client_id is required`)
    if (typeof rec.name !== 'string' || !rec.name) throw new Error(`OP_CLIENT_SEED[${i}]: name is required`)
    if (rec.class !== undefined && rec.class !== DEVICE_CLASS && rec.class !== SERVICE_CLASS) {
      throw new Error(`OP_CLIENT_SEED[${i}]: class must be "${DEVICE_CLASS}" or "${SERVICE_CLASS}" when declared (absent = the application class)`)
    }
    const isDevice = rec.class === DEVICE_CLASS
    const isService = rec.class === SERVICE_CLASS
    const isMachine = isDevice || isService
    if (rec.redirect_uris !== undefined && (!Array.isArray(rec.redirect_uris) || rec.redirect_uris.some(u => typeof u !== 'string'))) {
      throw new Error(`OP_CLIENT_SEED[${i}]: redirect_uris must be a list of strings`)
    }
    if (!isMachine && rec.redirect_uris === undefined) {
      throw new Error(`OP_CLIENT_SEED[${i}]: redirect_uris is required (the application class's exact URIs)`)
    }
    if (isMachine && (rec.redirect_uris?.length ?? 0) > 0) {
      throw new Error(`OP_CLIENT_SEED[${i}]: the ${rec.class} class carries no redirect_uris (nothing redirects — client_credentials only)`)
    }
    if (rec.secret !== undefined && typeof rec.secret !== 'string') throw new Error(`OP_CLIENT_SEED[${i}]: secret must be a string`)
    if (isMachine && typeof rec.secret !== 'string') {
      throw new Error(`OP_CLIENT_SEED[${i}]: the ${rec.class} class is confidential — secret is required (the machine caller authenticates with it)`)
    }
    const policy = rec.claims_policy as { claims?: unknown; roles?: unknown } | undefined
    if (policy !== undefined && (!Array.isArray(policy?.claims) || policy.claims.some(c => typeof c !== 'string'))) {
      throw new Error(`OP_CLIENT_SEED[${i}]: claims_policy.claims must be a list of strings`)
    }
    // TODO.identity/03: the optional role allowlist — the closed set of
    // roles the ID token may carry for this client.
    if (policy?.roles !== undefined && (!Array.isArray(policy.roles) || policy.roles.some(r => typeof r !== 'string'))) {
      throw new Error(`OP_CLIENT_SEED[${i}]: claims_policy.roles must be a list of role ids`)
    }
    if (isDevice && policy !== undefined) {
      throw new Error(`OP_CLIENT_SEED[${i}]: the device class's claims are fixed by the class (the device id, its org, its instrument model) — claims_policy never applies`)
    }
    if (isService && policy !== undefined) {
      throw new Error(`OP_CLIENT_SEED[${i}]: the service class's claims are fixed by the class (the service id, its org, the audience, the scope allowlist) — claims_policy never applies`)
    }
    if (isDevice) {
      const { device, error } = validateDeviceBlock(rec.device)
      if (error) throw new Error(`OP_CLIENT_SEED[${i}]: ${error}`)
      rec.device = device
    } else if (rec.device !== undefined) {
      throw new Error(`OP_CLIENT_SEED[${i}]: the device block rides class "${DEVICE_CLASS}" — declare the class, or drop the block`)
    }
    if (isService) {
      const { service, error } = validateServiceBlock(rec.service)
      if (error) throw new Error(`OP_CLIENT_SEED[${i}]: ${error}`)
      rec.service = service
    } else if (rec.service !== undefined) {
      throw new Error(`OP_CLIENT_SEED[${i}]: the service block rides class "${SERVICE_CLASS}" — declare the class, or drop the block`)
    }
    // The SSO home's launch card: validated at the seed like every other
    // field — a misdeclared card fails the boot, never renders broken.
    if (rec.launch !== undefined) {
      if (isMachine) throw new Error(`OP_CLIENT_SEED[${i}]: the ${rec.class} class never joins the SSO home (the launcher is a human surface) — no launch card`)
      const { error } = validateLaunch(rec.launch as LaunchInput)
      if (error) throw new Error(`OP_CLIENT_SEED[${i}]: ${error}`)
    }
    return rec as unknown as OpClientSeedEntry
  })
}

/** Upsert the seed into the registry. Answers the seeded client ids. */
export async function seedOidcClientsFromEnv(env: EnvLike, store: ServerStore): Promise<string[]> {
  const raw = env.OP_CLIENT_SEED?.trim()
  if (!raw) return []
  const seeded: string[] = []
  for (const entry of parseOpClientSeed(raw)) {
    // The class marker + the machine block ride the policy JSON (the
    // column round-trips opaquely — the machine classes are data-level
    // extensions, auth/op/device-clients.ts's + service-clients.ts's
    // doctrine).
    const policy: OpClientPolicy | OpServicePolicy | null = entry.class === DEVICE_CLASS
      ? { claims: [], class: DEVICE_CLASS, device: entry.device! }
      : entry.class === SERVICE_CLASS
        ? { claims: [], class: SERVICE_CLASS, service: entry.service! }
        : entry.claims_policy
          ? { claims: entry.claims_policy.claims, ...(entry.claims_policy.roles ? { roles: entry.claims_policy.roles } : {}) }
          : null
    await store.upsertOidcClient({
      clientId: entry.client_id,
      name: entry.name,
      secretHash: entry.secret ? await hashClientSecret(entry.secret) : null,
      redirectUris: entry.redirect_uris ?? [],
      claimsPolicy: policy,
      createdBy: 'op-client-seed',
    })
    // The launch metadata rides a SEPARATE write (the upsert never
    // touches the launch columns): a seed entry declares the card only
    // when it carries one, so a re-seed of the protocol fields keeps the
    // admin's launcher edits.
    if (entry.launch !== undefined) {
      const { launch } = validateLaunch(entry.launch)
      await store.setOidcClientLaunch(entry.client_id, launch)
    }
    seeded.push(entry.client_id)
  }
  return seeded
}
