// ═══════════════════════════════════════════════════════════════════
// TODO.sota/07.4 — the CLIENT REGISTRY ADMIN module, extracted from
// op.ts as the fifth proof of the domain-model split (the pure
// refactor; the golden + the suite are the proof — zero behavior
// change).
//
// The same gate as the identity admin (routes/auth.ts): the platform
// admin and the scheme operator manage relying parties. The secret is
// write-only (hashed on receipt, never listed back); a GENERATED secret
// (TODO.identity/07's registration wizard) is answered exactly once, in
// the registration response, and only its hash survives. Every mutation
// lands an auditEvents row (the registry's activity view) — the audit
// helper rides in as a dependency (op.ts's registry-audit closure; the
// same discipline as routes/op-accounts.ts: the audit never blocks the
// path).
//
//   GET  /api/op/clients            — the registry.
//   POST /api/op/clients            — register/refresh a client (the
//        application class; the machine classes below).
//   POST /api/op/clients/:id/status — enable/disable. A disabled client
//        is refused at authorize AND token, its rows kept (the audit
//        trail). On a machine client the disable IS the revocation (the
//        machine cone has no other lifecycle act — the chain names the
//        class honestly).
//
// THE MACHINE CLASSES (the machine cone, auth/op/device-clients.ts +
// service-clients.ts): `class: "device"` registers a NON-HUMAN,
// per-device client binding `device: { id, org, instrument_model }`;
// `class: "service"` registers a NON-HUMAN, per-service-account client
// binding `service: { id, org, audience, scopes }`. Both:
// client_credentials only, always confidential, no redirect_uris, no
// launch card, no user claims; the org must resolve on the organization
// registry (the token's org claim names an org this OP knows). The
// class is FIXED AT REGISTRATION: an edit never declares a class the
// stored row does not carry (an application row refuses a machine
// `class`; a machine row's edit omits `class` and keeps its class).
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { getStore, type AuthUserPayload, type OidcClient, type OidcClientLaunch } from '../store'
import { sessionUser } from '../session'
import { isSystemAuthority, APP_ROLES } from '../vocab/roles'
import { hashClientSecret } from '../auth/op/secrets'
import { opRandomToken } from '../auth/op/keys'
import { validateLaunch, type LaunchInput } from '../auth/op/launch'
import {
  DEVICE_CLASS, deviceClassOf, validateDeviceBlock,
  type DeviceClientClaims, type OpClientPolicy,
} from '../auth/op/device-clients'
import {
  SERVICE_CLASS, serviceClassOf, validateServiceBlock,
  type OpServicePolicy, type ServiceClientClaims,
} from '../auth/op/service-clients'
import { logoutBlockOf, validateLogoutBlock, type OpLogoutBlock, type OpLogoutPolicy } from '../auth/op/logout'
import { resolveRegistryOrg } from '../auth/org-registry'

type AuditFn = (
  action: string,
  entityId: string,
  actor: { userId?: string; userName?: string },
  metadata: Record<string, unknown>,
) => Promise<void>

async function requireAdmin(c: Context): Promise<{ user: AuthUserPayload | null; error: Response | null }> {
  const user = await sessionUser(c)
  if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
  if (!isSystemAuthority(user.role)) {
    return { user: null, error: c.json({ error: 'administrator role required' }, 403) }
  }
  return { user, error: null }
}

/** A registry row's PUBLIC view (never the secret hash). The machine
 *  classes (the machine cone) read honestly: `class` + the bound
 *  device/service block derive from the stored policy. */
function clientView(client: OidcClient) {
  const device = deviceClassOf(client.claimsPolicy)
  const service = device ? null : serviceClassOf(client.claimsPolicy)
  return {
    clientId: client.clientId,
    name: client.name,
    class: device ? DEVICE_CLASS : service ? SERVICE_CLASS : 'application',
    device,
    service,
    redirectUris: client.redirectUris,
    claimsPolicy: client.claimsPolicy,
    // TODO.identity-sso (the wave-A tail): the registered logout surface
    // (the end-session redirect's allowlist) + the backchannel receiver.
    logout: logoutBlockOf(client.claimsPolicy),
    // The SSO home's launch card (null = the client is not on the
    // launcher — the machine classes NEVER are).
    launch: client.launch,
    confidential: !!client.secretHash,
    status: client.status,
    createdAt: client.createdAt,
    createdBy: client.createdBy,
  }
}

export function createOpClientsAdminRouter(deps: {
  ensureSeeded: (c: Context) => Promise<void>
  audit: AuditFn
}): Hono {
  const router = new Hono()
  const audit = deps.audit

  // GET /api/op/clients — the registry.
  router.get('/api/op/clients', async (c: Context) => {
    await deps.ensureSeeded(c)
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    return c.json((await getStore().listOidcClients()).map(clientView))
  })

  // POST /api/op/clients — register/refresh a client. `secret` present
  // re-keys the client; ABSENT keeps the stored hash (or a public
  // client); `secret: null` (explicit) makes the client public.
  // `generate_secret: true` (TODO.identity/07's wizard) mints the secret
  // server-side instead: the plaintext rides the response ONCE, only its
  // hash is stored; the two secret postures never mix in one call.
  router.post('/api/op/clients', async (c: Context) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<{
      client_id?: string
      name?: string
      secret?: string | null
      generate_secret?: boolean
      redirect_uris?: string[]
      claims_policy?: { claims?: unknown; roles?: unknown } | null
      /** TODO.identity-sso (the wave-A tail): the client's logout surface
       *  — the exact post-logout redirect URIs (the end-session redirect's
       *  allowlist) + the backchannel receiver. The application class
       *  only; the wholesale policy rewrite carries it (an edit that
       *  omits `logout` drops the stored block, exactly as with roles). */
      logout?: unknown
      launch?: LaunchInput | null
      class?: unknown
      device?: unknown
      service?: unknown
    }>().catch(() => null)
    if (!body || typeof body.client_id !== 'string' || !body.client_id.trim()) {
      return c.json({ error: 'client_id is required' }, 400)
    }
    if (typeof body.name !== 'string' || !body.name.trim()) {
      return c.json({ error: 'name is required' }, 400)
    }

    // The class resolution (fixed at registration): the stored row's
    // class wins on an edit; a create takes the body's declaration.
    const existing = await getStore().getOidcClient(body.client_id.trim())
    const existingDevice = deviceClassOf(existing?.claimsPolicy ?? null)
    const existingService = existingDevice ? null : serviceClassOf(existing?.claimsPolicy ?? null)
    if (body.class !== undefined && body.class !== DEVICE_CLASS && body.class !== SERVICE_CLASS) {
      return c.json({ error: `class must be "${DEVICE_CLASS}" or "${SERVICE_CLASS}" when declared (absent = the application class)` }, 400)
    }
    const declaredClass = body.class as typeof DEVICE_CLASS | typeof SERVICE_CLASS | undefined
    const existingClass = existingDevice ? DEVICE_CLASS : existingService ? SERVICE_CLASS : null
    if (existing && declaredClass !== undefined && declaredClass !== existingClass) {
      return c.json({ error: `the client class is fixed at registration — ${existing.clientId} is the ${existingClass ?? 'application'} class; register a fresh client for the ${declaredClass}` }, 400)
    }
    const isDevice = existing ? existingDevice !== null : declaredClass === DEVICE_CLASS
    const isService = existing ? existingService !== null : declaredClass === SERVICE_CLASS

    // THE MACHINE CLASSES' shape (the registry enforces it at write — the
    // token endpoint then trusts the class).
    let deviceBlock: DeviceClientClaims | null = null
    let serviceBlock: ServiceClientClaims | null = null
    if (isDevice) {
      if (body.device !== undefined) {
        const { device, error } = validateDeviceBlock(body.device)
        if (error) return c.json({ error }, 400)
        deviceBlock = device
      } else {
        deviceBlock = existingDevice // the edit keeps the stored binding
      }
      if (!deviceBlock) {
        return c.json({ error: 'the device class binds a device: device: { id, org, instrument_model } is required' }, 400)
      }
      // The org claim the twin endpoints consume names an org this OP
      // actually knows — resolved against the organization registry.
      if (!(await resolveRegistryOrg(getStore(), deviceBlock.org))) {
        return c.json({ error: `device.org '${deviceBlock.org}' is not on the organization registry — the device token's org claim must name an org this OP knows` }, 400)
      }
      if (body.redirect_uris !== undefined && (!Array.isArray(body.redirect_uris) || body.redirect_uris.length > 0)) {
        return c.json({ error: 'the device class carries no redirect_uris (nothing redirects — client_credentials only)' }, 400)
      }
      if (body.launch) {
        return c.json({ error: 'a device client never joins the SSO home (the launcher is a human surface) — no launch card' }, 400)
      }
      const deviceClaims = body.claims_policy?.claims
      if ((Array.isArray(deviceClaims) && deviceClaims.length > 0) || body.claims_policy?.roles !== undefined) {
        return c.json({ error: 'the device class’s claims are fixed by the class (the device id, its org, its instrument model) — the policy never carries user claims' }, 400)
      }
      if (body.secret === null) {
        return c.json({ error: 'a device client is confidential — it never goes public (the secret is the device’s credential)' }, 400)
      }
      if (!existing && body.generate_secret !== true && !(typeof body.secret === 'string' && body.secret)) {
        return c.json({ error: 'a device client is confidential — pass generate_secret (the server mints it, shown once) or secret' }, 400)
      }
      if (body.service !== undefined) {
        return c.json({ error: `the service block rides class "${SERVICE_CLASS}" — declare the class, or drop the block` }, 400)
      }
      if (body.logout !== undefined) {
        return c.json({ error: 'the device class has no logout surface — nothing signs in through it, nothing logs out (client_credentials only)' }, 400)
      }
    } else if (isService) {
      if (body.service !== undefined) {
        const { service, error } = validateServiceBlock(body.service)
        if (error) return c.json({ error }, 400)
        serviceBlock = service
      } else {
        serviceBlock = existingService // the edit keeps the stored binding
      }
      if (!serviceBlock) {
        return c.json({ error: 'the service class binds a service account: service: { id, org, audience, scopes } is required' }, 400)
      }
      // The org claim the called service consumes names an org this OP
      // actually knows — resolved against the organization registry.
      if (!(await resolveRegistryOrg(getStore(), serviceBlock.org))) {
        return c.json({ error: `service.org '${serviceBlock.org}' is not on the organization registry — the service token's org claim must name an org this OP knows` }, 400)
      }
      if (body.redirect_uris !== undefined && (!Array.isArray(body.redirect_uris) || body.redirect_uris.length > 0)) {
        return c.json({ error: 'the service class carries no redirect_uris (nothing redirects — client_credentials only)' }, 400)
      }
      if (body.launch) {
        return c.json({ error: 'a service client never joins the SSO home (the launcher is a human surface) — no launch card' }, 400)
      }
      const serviceClaims = body.claims_policy?.claims
      if ((Array.isArray(serviceClaims) && serviceClaims.length > 0) || body.claims_policy?.roles !== undefined) {
        return c.json({ error: 'the service class’s claims are fixed by the class (the service id, its org, the audience, the scope allowlist) — the policy never carries user claims' }, 400)
      }
      if (body.secret === null) {
        return c.json({ error: 'a service client is confidential — it never goes public (the secret is the service account’s credential)' }, 400)
      }
      if (!existing && body.generate_secret !== true && !(typeof body.secret === 'string' && body.secret)) {
        return c.json({ error: 'a service client is confidential — pass generate_secret (the server mints it, shown once) or secret' }, 400)
      }
      if (body.device !== undefined) {
        return c.json({ error: `the device block rides class "${DEVICE_CLASS}" — declare the class, or drop the block` }, 400)
      }
      if (body.logout !== undefined) {
        return c.json({ error: 'the service class has no logout surface — nothing signs in through it, nothing logs out (client_credentials only)' }, 400)
      }
    } else {
      // THE APPLICATION CLASS (the relying-party posture — unchanged).
      if (body.device !== undefined || body.service !== undefined) {
        return c.json({ error: 'the device/service blocks ride their machine classes — declare the class, or drop the block' }, 400)
      }
      if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0 || body.redirect_uris.some(u => typeof u !== 'string' || !u)) {
        return c.json({ error: 'redirect_uris must be a non-empty list of exact URIs' }, 400)
      }
      for (const uri of body.redirect_uris) {
        try { new URL(uri) } catch { return c.json({ error: `redirect_uris entry ${JSON.stringify(uri)} is not an absolute URI` }, 400) }
      }
    }
    // TODO.identity-sso (the wave-A tail): the logout block, the
    // application class only (the machine branches refused above). An
    // all-empty block stores as NO logout surface (the key stays out of
    // the policy JSON — the tight-write doctrine).
    let logoutWrite: OpLogoutBlock | null = null
    if (body.logout !== undefined) {
      const { logout, error } = validateLogoutBlock(body.logout)
      if (error) return c.json({ error }, 400)
      logoutWrite = logout && (logout.post_logout_redirect_uris.length || logout.backchannel_logout_uri) ? logout : null
    }
    if (body.claims_policy != null && (!Array.isArray(body.claims_policy?.claims) || body.claims_policy.claims.some(x => typeof x !== 'string'))) {
      return c.json({ error: 'claims_policy.claims must be a list of claim names (roles, groups, org, picture, orcid, org_ror)' }, 400)
    }
    // TODO.identity/03 — the optional role allowlist: the closed set of
    // roles the ID token may carry for this client. A role outside the
    // platform vocabulary is a configuration bug, refused loudly (the OP
    // would never emit it anyway — better to fail at write time). The
    // machine classes never name it (the class checks above already
    // refused).
    const policyRoles = body.claims_policy?.roles
    if (policyRoles !== undefined) {
      if (!Array.isArray(policyRoles) || policyRoles.some(r => typeof r !== 'string')) {
        return c.json({ error: 'claims_policy.roles must be a list of role ids' }, 400)
      }
      const unknown = (policyRoles as string[]).filter(r => !(APP_ROLES as readonly string[]).includes(r))
      if (unknown.length) {
        return c.json({ error: `claims_policy.roles names unknown role(s): ${unknown.join(', ')}`, knownRoles: [...APP_ROLES] }, 400)
      }
    }
    if (body.generate_secret === true && typeof body.secret === 'string' && body.secret) {
      return c.json({ error: 'pass either secret or generate_secret, never both' }, 400)
    }
    // The SSO home's launch card (OPTIONAL): absent leaves the stored
    // metadata untouched (the protocol fields edit never disturbs the
    // launcher); null takes the client OFF the launcher; an object sets
    // the card, validated like the seed (auth/op/launch.ts). The machine
    // classes refused the card above.
    let launchWrite: OidcClientLaunch | null | undefined = undefined
    if (body.launch === null) launchWrite = null
    else if (body.launch !== undefined) {
      const { launch, error } = validateLaunch(body.launch)
      if (error) return c.json({ error }, 400)
      launchWrite = launch
    }

    const generatedSecret = body.generate_secret === true ? opRandomToken() : null
    const secretHash = generatedSecret
      ? await hashClientSecret(generatedSecret)
      : typeof body.secret === 'string' && body.secret
        ? await hashClientSecret(body.secret)
        : body.secret === null
          ? null
          : existing?.secretHash ?? null
    // The class marker + the machine block ride the policy JSON (the store
    // seam round-trips it opaquely — the data-level extension). The
    // wave-A tail's logout block rides the same JSON (the application
    // class); the wholesale rewrite doctrine stands — an edit that omits
    // `logout` drops the stored block, exactly as with roles.
    const policy: OpClientPolicy | OpServicePolicy | OpLogoutPolicy | null = isDevice
      ? { claims: [], class: DEVICE_CLASS, device: deviceBlock! }
      : isService
        ? { claims: [], class: SERVICE_CLASS, service: serviceBlock! }
        : body.claims_policy || logoutWrite
          ? {
              claims: (body.claims_policy?.claims as string[] | undefined) ?? [],
              ...(policyRoles ? { roles: policyRoles as string[] } : {}),
              ...(logoutWrite ? { logout: logoutWrite } : {}),
            }
          : null
    const client = await getStore().upsertOidcClient({
      clientId: body.client_id.trim(),
      name: body.name.trim(),
      secretHash,
      redirectUris: isDevice || isService ? [] : body.redirect_uris!,
      claimsPolicy: policy,
      createdBy: gate.user.email,
    })
    // The launch card rides its own write (the upsert never touches the
    // launch columns — a protocol-fields edit keeps the stored card).
    const settled = launchWrite === undefined
      ? client
      : (await getStore().setOidcClientLaunch(client.clientId, launchWrite))!
    await audit(existing ? 'client.updated' : 'client.registered', client.clientId, { userId: gate.user.id, userName: gate.user.name }, {
      name: client.name,
      class: isDevice ? DEVICE_CLASS : isService ? SERVICE_CLASS : 'application',
      // The machine act names the bound caller (register / rotate-secret /
      // revoke all read off the same chain).
      ...(isDevice && deviceBlock ? { device: deviceBlock } : {}),
      ...(isService && serviceBlock ? { service: serviceBlock } : {}),
      confidential: !!client.secretHash,
      rekeyed: !!generatedSecret || typeof body.secret === 'string',
      made_public: body.secret === null,
      redirect_uris: client.redirectUris.length,
      claims: client.claimsPolicy?.claims ?? [],
      // The logout surface's write (undefined = untouched, null = cleared,
      // the block = as written) — the wholesale policy doctrine's record.
      ...(body.logout !== undefined ? { logout: logoutWrite } : {}),
      // The launch write's record (undefined = untouched, null = off
      // the launcher, object = the card as written).
      ...(launchWrite !== undefined ? { launch: launchWrite } : {}),
    })
    return c.json(
      generatedSecret ? { ...clientView(settled), secret: generatedSecret } : clientView(settled),
      existing ? 200 : 201,
    )
  })

  // POST /api/op/clients/:id/status — enable/disable. A disabled client
  // is refused at authorize AND token, its rows kept (the audit trail).
  // On a machine client the disable IS the revocation (the machine cone
  // has no other lifecycle act — the chain names the class honestly).
  router.post('/api/op/clients/:id/status', async (c: Context) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<{ status?: string }>().catch(() => null)
    if (!body || (body.status !== 'active' && body.status !== 'disabled')) {
      return c.json({ error: 'status must be "active" or "disabled"' }, 400)
    }
    const client = await getStore().setOidcClientStatus(c.req.param('id') ?? '', body.status)
    if (!client) return c.json({ error: 'not found' }, 404)
    const device = deviceClassOf(client.claimsPolicy)
    const service = device ? null : serviceClassOf(client.claimsPolicy)
    await audit('client.status', client.clientId, { userId: gate.user.id, userName: gate.user.name }, {
      status: client.status,
      class: device ? DEVICE_CLASS : service ? SERVICE_CLASS : 'application',
      ...(device ? { device: device.id, org: device.org } : {}),
      ...(service ? { service: service.id, org: service.org, audience: service.audience } : {}),
    })
    return c.json(clientView(client))
  })

  return router
}
