// ═══════════════════════════════════════════════════════════════════
// The deployment profile — the IDENTITY service's own (TODO.restructure/23
// pruned the platform's four-posture taxonomy this module was born with):
// every deployment of this service is an OIDC Provider instance — the
// central one, or a whitelabeled IA/TL tenant (TODO.restructure/16-21).
// The profile declares who THIS instance is (its own organization
// identity + participant kind), its brand, its console sections, its
// peers. The PLATFORM integrates the other way: by CONFIGURATION — its
// RP registration — never by entries hardcoded here. Profiles gate
// routes, nav, consoles, and seeds.
//
// This module is the WORKER-SAFE core: the schema, the module catalog,
// the defaults per role set (the 00 module map), the parser (profile
// YAML text → the effective profile), the isolate-level install slot
// (the same pattern db/backend.ts uses for the store), and the
// profile-aware account/organization seed plans. The NODE disk loader
// (INSTANCE_PROFILE env path, else <consumer root>/instance.profile.yaml
// — the consumer passes its root; the kernel never anchors at its own
// package root) lives in ./profile/node.ts — never imported by the
// Worker bundle.
//
// The DEFAULT is the hub profile: a boot with no profile file behaves
// byte-identically to the pre-profiles app. The client learns the
// profile from /api/config (see src/persistence/instance-profile.ts).
//
// Naming: this is the INSTANCE/deployment profile — a different concept
// from the PERSISTENCE profile (src/persistence/profile.ts, which store
// backend the workspace uses). The two never share a name.
// ═══════════════════════════════════════════════════════════════════

import { load as parseYaml } from 'js-yaml'
import { DEMO_ACCOUNTS } from './store'

// ── The vocabulary ──────────────────────────────────────────────────

// TODO.restructure/23 — TWO vocabularies, one union: the values are the
// OIML participant kinds an organization may play (the org-facing
// `role_codes`); a DEPLOYMENT of this service always plays exactly one
// role: 'identity' (the parse enforces it). The platform's hub/ia/tl
// deployment postures were the kernel's, never this service's.
export const PROFILE_ROLES = ['hub', 'ia', 'tl', 'identity'] as const
export type ProfileRole = (typeof PROFILE_ROLES)[number]

/** The modules this service toggles — its OP surface alone (the
 *  catalog order is the canonical display/serialization order). */
// TODO.restructure/23 — the platform's module taxonomy is NOT identity's
// (the platform integrates by CONFIGURATION: its RP registration, never
// module entries hardcoded here). Identity's own catalog is its OP
// surface alone.
export const INSTANCE_MODULES = [
  'identity',    // the OIDC Provider (TODO.identity/01): discovery, JWKS, authorize/consent, token, userinfo
] as const
export type InstanceModule = (typeof INSTANCE_MODULES)[number]

export interface ProfileIdentity {
  /** The id the workflow records reference for this instance's own org:
   *  the IA's oiml_code ('EX1'-style) when the instance plays `ia`; the
   *  TL's oiml_id in string form ('21'-style) when it plays only `tl`. */
  org_id: string
  org_name: string
  /** The OIML-CS participant roles the instance's own org plays. */
  role_codes: ProfileRole[]
  /** The TL organization's id (its numeric oiml_id in string form) when
   *  the instance plays `tl` and the TL id differs from org_id — the
   *  combined NMI (ia+tl) case. Defaults to org_id. Must be numeric. */
  tl_org_id?: string
  country?: string
}

export interface FederationPeer {
  id: string
  name?: string
  roles?: string[]
  endpoint?: string
  /** The peer's submission public key — managed by TODO.federation/04;
   *  the profile only carries the placeholder list. */
  public_key?: string
}

/** The resolved identity (post-parse): `country` settled to a string. */
export interface ResolvedIdentity extends ProfileIdentity {
  country: string
}

/** The EFFECTIVE profile — parsed, validated, and resolved (modules
 *  expanded from the role-set defaults when not spelled out and the
 *  demo-personas flag settled). */
export interface InstanceProfile {
  identity: ResolvedIdentity
  roles: ProfileRole[]
  modules: InstanceModule[]
  peers: FederationPeer[]
  /** The whitelabel brand (TODO.restructure/17): the name (required,
   *  defaulting to the org's) plus the OPTIONAL asset paths and copy —
   *  every field the client's IdentityBranding carries, each overridable
   *  per deployment, all projected by /api/config. */
  branding: {
    name: string
    logoLight?: string
    logoDark?: string
    markLight?: string
    markDark?: string
    loginTagline?: string
    supportUrl?: string
  }
  /** The admin console's declared section set (TODO.restructure/17 — the
   *  kind-projected nav, a CONFIGURATION act): the keys of the shell's
   *  ADMIN_ENTRIES, in any order; null (undeclared) = the full default
   *  set. A whitelabel flavor narrows the console by DECLARING fewer
   *  sections — the code never branches on the instance's kind. */
  console: { sections: string[] } | null
  /** Seed the demo cast alongside the instance identity. Resolved from
   *  `demo_personas:` (the SEED_DEMO_PERSONAS env flag forces on, never
   *  off); the hub DEFAULTS it on (the historical default), so a hub
   *  carrying `demo_personas: false` skips the cast everywhere — the
   *  account seed, and the demo sign-in surface alongside
   *  (TODO.demo-ops/01, the production posture: identity.ts's
   *  demoAccountsEnabled reads this same flag). */
  demoPersonas: boolean
  /** TODO.demo-ops/04 — the demonstration-environment signage: `demo:
   *  true` renders the persistent "Demonstration environment" banner on
   *  every page (components/DemoBanner.vue, reading this flag through
   *  /api/config) and opens the guided-demo entry on the login page.
   *  Deliberately SEPARATE from demoPersonas: the cast flag answers
   *  "does this instance carry the fictional accounts" (a seeding and
   *  sign-in question), this one answers "is this whole instance a
   *  demonstration" (an honesty signal). They coincide on the demo
   *  instances (demo/nmi/tl); the PR previews keep the cast WITHOUT the
   *  banner (operator-facing, transient), and a training instance could
   *  carry the banner without the cast. Defaults off everywhere. */
  demo: boolean
}

// ── The defaults (the TODO.federation/00 module map) ────────────────

/** The module set a profile boots with when it does not spell
 *  `modules:` out: the OP surface, always (TODO.restructure/23 — the
 *  00 module map was the platform's). */
export function defaultModulesForRoles(roles: ProfileRole[]): InstanceModule[] {
  // TODO.restructure/23: an identity deployment serves the OP contract
  // and nothing else — the platform's surfaces are the platform's
  // configuration, never identity's defaults.
  return roles.includes('identity') ? ['identity'] : []
}

/**
 * The built-in fallback — the IDENTITY SERVICE's own profile (never a
 * platform posture; TODO.restructure/23), used only when no profile
 * file loads at all (a dev boot without INSTANCE_PROFILE). */
export function defaultInstanceProfile(): InstanceProfile {
  return {
    identity: { org_id: 'oimlsmart-id', org_name: 'OIML SMART Identity', role_codes: ['identity'], country: '' },
    roles: ['identity'],
    modules: ['identity'],
    peers: [],
    branding: { name: 'OIML SMART Identity' },
    console: null,
    demoPersonas: true,
    demo: false,
  }
}

// ── Parse + validate + resolve ───────────────────────────────────────

function fail(message: string): never {
  throw new Error(`instance profile: ${message}`)
}

function asStringList(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some(v => typeof v !== 'string')) {
    fail(`${field} must be a list of strings`)
  }
  return value as string[]
}

/** The TL organization id for the identity (the oiml_id string form). */
export function tlOrgIdOf(identity: ProfileIdentity): string {
  return identity.tl_org_id ?? identity.org_id
}

export interface ParseEnv {
  /** The SEED_DEMO_PERSONAS env flag resolution (node: process.env; the
   *  Worker: the binding) — true forces the demo cast on, anything else
   *  defers to the profile file. */
  demoPersonas?: boolean
}

/**
 * The parser: profile YAML text → the effective profile. `undefined`
 * text means "no profile file" and answers the built-in hub default —
 * the byte-identical-today posture. Throws (fails the boot) on a
 * declared-but-invalid profile: a misdeclared instance must never boot
 * into a guessed configuration.
 *
 * Tolerance rules (the shared profile file is read by three waves —
 * TODO.federation/10's OIDC identity: seam, TODO.federation/09's
 * branding: section, and this loader; unknown keys pass through):
 * `identity.id`/`identity.name` are accepted as aliases of
 * `org_id`/`org_name` (fed-09's fixtures use the short forms); `roles`
 * omitted defaults to the identity's role_codes (else [hub]); an
 * `identity` section without org fields is only valid on the hub role
 * set (the hub seeds no identity org — the org fields matter exactly
 * when the instance plays ia/tl).
 */
export function parseInstanceProfile(yamlText: string | undefined, env?: ParseEnv): InstanceProfile {
  if (yamlText === undefined) return defaultInstanceProfile()
  const raw = parseYaml(yamlText) as unknown
  if (raw === null || raw === undefined) return defaultInstanceProfile()
  if (typeof raw !== 'object' || Array.isArray(raw)) fail('the profile must be a mapping')

  const doc = raw as Record<string, unknown>

  // identity (optional on the hub; required for ia/tl)
  const identityRaw = doc.identity
  if (typeof identityRaw !== 'undefined' && (typeof identityRaw !== 'object' || identityRaw === null)) {
    fail('identity must be a mapping (org_id, org_name, role_codes — and/or the OIDC fields TODO.federation/10 reads)')
  }
  const identityIn = (identityRaw ?? {}) as Record<string, unknown>
  // The fed-09 spelling (identity.id / identity.name) aliases the
  // fed-01 one (org_id / org_name) — one file, both readers.
  const orgId = identityIn.org_id ?? identityIn.id
  const orgName = identityIn.org_name ?? identityIn.name

  // roles (optional — defaults to the identity's role_codes, else hub)
  const rolesIn = typeof doc.roles === 'undefined' ? undefined : asStringList(doc.roles, 'roles')
  const roleCodesIn = asStringList(identityIn.role_codes ?? [], 'identity.role_codes') as ProfileRole[]
  const roles = (rolesIn ?? (roleCodesIn.length ? roleCodesIn : ['identity'])) as ProfileRole[]
  if (!roles.length) fail('roles must name the deployment role')
  for (const r of roles) {
    if (!(PROFILE_ROLES as readonly string[]).includes(r)) fail(`roles: unknown role "${r}"`)
  }
  // TODO.identity/01 + TODO.restructure/23: every deployment of this
  // service is an OIDC Provider instance — the platform's hub/ia/tl
  // postures are not identity's, and the service never plays two roles.
  if (roles.length !== 1 || roles[0] !== 'identity') fail("roles must be exactly [identity] — this service is an OIDC Provider deployment (the platform postures are the platform's, never this service's)")

  if (typeof orgId !== 'string' || !orgId) fail('identity.org_id (or identity.id) is required (the org this instance is)')
  if (typeof orgName !== 'string' || !orgName) fail('identity.org_name (or identity.name) is required')
  for (const rc of roleCodesIn) {
    if (!(PROFILE_ROLES as readonly string[]).includes(rc)) fail(`identity.role_codes: unknown role code "${rc}"`)
  }
  if (typeof identityIn.tl_org_id !== 'undefined' && typeof identityIn.tl_org_id !== 'string' && typeof identityIn.tl_org_id !== 'number') {
    fail('identity.tl_org_id must be the TL oiml_id (a number or its string form)')
  }
  const identity: ProfileIdentity = {
    org_id: typeof orgId === 'string' && orgId ? orgId : 'biml',
    org_name: typeof orgName === 'string' && orgName ? orgName : 'BIML',
    role_codes: roleCodesIn.length ? roleCodesIn : roles,
    ...(typeof identityIn.tl_org_id !== 'undefined' ? { tl_org_id: String(identityIn.tl_org_id) } : {}),
    ...(typeof identityIn.country === 'string' ? { country: identityIn.country } : {}),
  }

  if (identity.role_codes.includes('tl')) {
    const tlId = tlOrgIdOf(identity)
    if (!/^\d+$/.test(tlId)) {
      // NOT a boot failure: a non-registry TL id (fed-09's branding
      // fixtures) skips the identity TL org record at seed time (the
      // role surfaces still gate on the module map) — the seed logs the
      // skip loudly. Declare identity.tl_org_id (numeric) for the
      // registry-honest record.
      console.warn(`instance profile: identity: TL id "${tlId}" is not a registry number (oiml_id) — the identity TL org record will not be seeded (set identity.tl_org_id to seed it)`)
    }
  }

  // modules (optional — defaults per the role set). TWO forms converge
  // on the same section: a LIST is the exact enabled set; a MAP of
  // {module: boolean} is a delta over the role-set defaults (the
  // (the explicit `modules:` spelling remains supported — the OP
  // surface is the only value in identity's catalog).
  let modules: InstanceModule[]
  if (typeof doc.modules === 'undefined') {
    modules = defaultModulesForRoles(roles)
  } else if (Array.isArray(doc.modules)) {
    const declared = asStringList(doc.modules, 'modules')
    for (const m of declared) {
      if (!(INSTANCE_MODULES as readonly string[]).includes(m)) fail(`modules: unknown module "${m}" (the catalog: ${INSTANCE_MODULES.join(', ')})`)
    }
    const set = new Set(declared as InstanceModule[])
    modules = INSTANCE_MODULES.filter(m => set.has(m))
  } else if (typeof doc.modules === 'object' && doc.modules !== null) {
    const set = new Set(defaultModulesForRoles(roles))
    for (const [m, on] of Object.entries(doc.modules as Record<string, unknown>)) {
      if (!(INSTANCE_MODULES as readonly string[]).includes(m)) fail(`modules: unknown module "${m}" (the catalog: ${INSTANCE_MODULES.join(', ')})`)
      if (typeof on !== 'boolean') fail(`modules.${m} must be a boolean`)
      if (on) set.add(m as InstanceModule)
      else set.delete(m as InstanceModule)
    }
    modules = INSTANCE_MODULES.filter(m => set.has(m))
  } else {
    fail('modules must be a list (the exact enabled set) or a map of {module: boolean} (a delta over the role-set defaults)')
  }

  // peers (placeholder list — TODO.federation/04 manages them)
  const peersRaw = doc.peers ?? []
  if (!Array.isArray(peersRaw)) fail('peers must be a list')
  const peers: FederationPeer[] = peersRaw.map((p, i) => {
    if (typeof p !== 'object' || p === null || typeof (p as Record<string, unknown>).id !== 'string') {
      fail(`peers[${i}] must carry at least an id`)
    }
    return p as FederationPeer
  })

  // branding (TODO.restructure/17: the whitelabel fields, all optional,
  // every one a URL path or a line of copy — never code)
  const brandingRaw = doc.branding as Record<string, unknown> | undefined
  const brandString = (key: string): string | undefined => {
    const v = brandingRaw?.[key]
    return typeof v === 'string' && v.trim() ? v.trim() : undefined
  }
  const branding = {
    name: typeof brandingRaw?.name === 'string' && brandingRaw.name ? brandingRaw.name : identity.org_name,
    ...(brandString('logo_light') ? { logoLight: brandString('logo_light') } : {}),
    ...(brandString('logo_dark') ? { logoDark: brandString('logo_dark') } : {}),
    ...(brandString('mark_light') ? { markLight: brandString('mark_light') } : {}),
    ...(brandString('mark_dark') ? { markDark: brandString('mark_dark') } : {}),
    ...(brandString('login_tagline') ? { loginTagline: brandString('login_tagline') } : {}),
    ...(brandString('support_url') ? { supportUrl: brandString('support_url') } : {}),
  }

  // the console's declared section set (TODO.restructure/17 — the
  // kind-projected nav): the shell's KNOWN admin keys, fail-loud on an
  // unknown one (a typo narrows the console silently otherwise)
  const ADMIN_SECTION_KEYS = ['overview', 'registry', 'organizations', 'sessions', 'clients', 'activity', 'providers', 'security', 'users']
  const consoleRaw = doc.console as Record<string, unknown> | undefined
  let consoleSections: { sections: string[] } | null = null
  if (consoleRaw !== undefined) {
    const list = consoleRaw.sections
    if (!Array.isArray(list) || list.length === 0 || !list.every((s): s is string => typeof s === 'string')) {
      fail('console.sections must be a non-empty list of section keys')
    }
    for (const s of list) {
      if (!ADMIN_SECTION_KEYS.includes(s)) {
        fail(`console.sections names '${s}' — not one of the known admin sections (${ADMIN_SECTION_KEYS.join(', ')})`)
      }
    }
    consoleSections = { sections: list }
  }

  // demo personas: the env flag forces on; else the file's field; else
  // hub default on / non-hub default off.
  const fileFlag = typeof doc.demo_personas === 'boolean' ? doc.demo_personas : undefined
  const demoPersonas = env?.demoPersonas ?? fileFlag ?? roles.includes('hub')

  // the demo signage (TODO.demo-ops/04): an explicit boolean, default
  // off — the banner is a deliberate declaration, never inherited.
  if (typeof doc.demo !== 'undefined' && typeof doc.demo !== 'boolean') {
    fail('demo must be a boolean (true marks the instance a demonstration environment — the banner on every page)')
  }
  const demo = doc.demo === true


  return {
    identity: {
      org_id: identity.org_id,
      org_name: identity.org_name,
      role_codes: identity.role_codes,
      country: identity.country ?? '',
      ...(identity.tl_org_id ? { tl_org_id: identity.tl_org_id } : {}),
    },
    roles,
    modules,
    peers,
    branding,
    console: consoleSections,
    demoPersonas,
    demo,
  }
}

/** The Worker half of the loader: the profile arrives as an inline YAML
 *  binding (INSTANCE_PROFILE_YAML), never a disk path. */
export function resolveInstanceProfileFromEnv(env: { INSTANCE_PROFILE_YAML?: string; SEED_DEMO_PERSONAS?: string }): InstanceProfile {
  return parseInstanceProfile(env.INSTANCE_PROFILE_YAML, {
    demoPersonas: env.SEED_DEMO_PERSONAS === 'true' || env.SEED_DEMO_PERSONAS === '1' ? true : undefined,
  })
}

// ── The install slot (the db/backend.ts store pattern) ──────────────

let installed: InstanceProfile | null = null

/** The composition roots install the effective profile once per
 *  process / per isolate (node: profile-node.ts's loader; the Worker:
 *  per request from the env binding). */
export function installInstanceProfile(profile: InstanceProfile): void {
  installed = profile
}

/** The installed profile — the built-in HUB default when nothing was
 *  installed, so a boot with no profile declaration behaves exactly as
 *  the pre-profiles app (tests included). */
export function getInstanceProfile(): InstanceProfile {
  return installed ?? defaultInstanceProfile()
}

/** Test seam: re-arm the slot (the next getInstanceProfile reads the
 *  default again). */
export function resetInstanceProfileForTest(): void {
  installed = null
}

// ── The public view (the /api/config payload) ───────────────────────

/** The profile shape the client sees: deployment metadata only. */
export interface InstanceProfileView {
  identity: InstanceProfile['identity']
  roles: ProfileRole[]
  modules: InstanceModule[]
  peers: FederationPeer[]
  console: { sections: string[] } | null
  branding: { name: string }
  demoPersonas: boolean
  /** The demonstration-environment signage flag (TODO.demo-ops/04). */
  demo: boolean
}

export function publicProfileView(profile: InstanceProfile): InstanceProfileView {
  return {
    identity: profile.identity,
    roles: profile.roles,
    modules: profile.modules,
    peers: profile.peers,
    branding: profile.branding,
    console: profile.console,
    demoPersonas: profile.demoPersonas,
    demo: profile.demo,
  }
}

/** The effective module set projected as the full-catalog toggle map
 *  (the TODO.federation/02 `modules` key's shape on /api/config): every
 *  catalog id with its on/off — the toggle readers' fail-open rule then
 *  gates from the SAME truth as the instanceProfile view. */
export function projectModuleToggles(profile: InstanceProfile): Record<string, boolean> {
  const on = new Set(profile.modules)
  return Object.fromEntries(INSTANCE_MODULES.map(m => [m, on.has(m)]))
}

// ── The profile-aware seed plans ─────────────────────────────────────

export interface AccountSeed {
  email: string
  name: string
  role: string
  orgId: string | null
  /** The FULL assigned role set (the users.roles column) — absent = the
   *  primary role only (TODO.register/02: the demo applicant's org_admin
   *  rides this). */
  roles?: string[]
}

/**
 * The accounts a profile seeds. The hub seeds the demo cast, exactly as
 */
export function seedAccountsForProfile(profile: InstanceProfile): AccountSeed[] {
  // TODO.restructure/23: identity's implicit seed is the demo cast (the
  // dev posture) and NOTHING else — real accounts arrive by
  // CONFIGURATION: OP_ACCOUNT_SEED (the bootstrap invites) or the
  // self-registration/join ceremonies. The platform's per-role staff
  // derivation is gone with its postures.
  return profile.demoPersonas ? [...DEMO_ACCOUNTS] : []
}

/**
 * The instance's own organization record(s) (non-hub profiles) — one
 * per role code the identity plays, in the SAME shapes the cs-data
 * registry mappings produce (cs-organizations.ts): the IA record keyed
 * on its oiml_code, the TL record on its oiml_id string. The hub seeds
 * NO identity org (the participant-registry seed owns organizations
 * there), so this answers [] for it.
 */
export function identityOrgRecords(profile: InstanceProfile): Array<Record<string, unknown>> {
  if (profile.roles.includes('hub')) return []
  const { identity } = profile
  const at = new Date().toISOString()
  const address = { street: '', city: '', country: identity.country, postal_code: '' }
  const contact = { person: '', email: '', phone: '' }
  const records: Array<Record<string, unknown>> = []
  if (identity.role_codes.includes('ia')) {
    records.push({
      id: identity.org_id,
      kind: 'issuing-authority',
      name: identity.org_name,
      short_name: identity.org_id,
      oiml_code: identity.org_id,
      country: identity.country,
      address,
      contact,
      oiml_scope: [],
      utilized_laboratory_ids: [],
      certificate_prefix: identity.org_id,
      created: at,
      modified: at,
    })
  }
  if (identity.role_codes.includes('tl')) {
    const tlId = tlOrgIdOf(identity)
    // The TL record's oiml_id is the registry number (numeric by type):
    // a non-numeric TL id (a branding-only fixture, TODO.federation/09)
    // skips the record honestly — the parser already warned at boot.
    if (/^\d+$/.test(tlId)) {
      records.push({
        id: tlId,
        kind: 'test-laboratory',
        name: identity.org_name,
        short_name: identity.org_name,
        oiml_id: Number(tlId),
        parent_oiml_code: '',
        address,
        contact,
        oiml_scope: [],
        capabilities: [],
        accreditation_scope: [],
        created: at,
        modified: at,
      })
    }
  }
  return records
}
