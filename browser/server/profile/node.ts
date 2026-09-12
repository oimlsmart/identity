// ═══════════════════════════════════════════════════════════════════
// The node half of the deployment-profile loader (TODO.federation/01):
// resolves the profile YAML from disk — the INSTANCE_PROFILE env path
// when declared, else <consumer root>/instance.profile.yaml when
// present, else the built-in hub default (the byte-identical-today
// posture) — parses it through the worker-safe core (./profile.ts),
// and installs it into the isolate slot the seed plans and /api/config
// read.
//
// The DEFAULT path anchors at the CONSUMER's root, never this
// package's own: the composition root passes its `root` (the smart
// monorepo's browser/server/profile-node.ts anchors it at the repo
// root from its own module location); an unrooted call falls back to
// the process's working directory. A kernel resolving its own
// import.meta.url here would look under packages/platform-server/
// (node_modules/@oimlsmart/platform-server/ once published) — a place
// no deployment profile ever lives, so a consumer's default file at
// its own root would be silently ignored (the wave-01 regression the
// root parameter fixes).
//
// NODE-ONLY (node:fs) — the Worker bundle never imports this module;
// the Worker's loader is profile.ts's resolveInstanceProfileFromEnv
// (the inline INSTANCE_PROFILE_YAML binding).
// ═══════════════════════════════════════════════════════════════════

import { existsSync, readFileSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import {
  installInstanceProfile,
  parseInstanceProfile,
  type InstanceProfile,
} from '../profile'

export interface LoadNodeProfileOptions {
  /** Override the file resolution (tests); still installs + memoizes. */
  path?: string
  /** The consumer's root for the default profile path
   *  (<root>/instance.profile.yaml) — the composition root's context.
   *  Defaults to the process's working directory. NEVER this package's
   *  own root: the kernel ships no default profile and never reads one
   *  from its own tree. */
  root?: string
  /** Re-read even when a profile is already loaded (tests). */
  force?: boolean
}

let loaded: InstanceProfile | null = null

/** The profile file this process boots from: $INSTANCE_PROFILE (relative
 *  paths resolve against the CWD — the `browser/` dir under npm run dev)
 *  when declared, else <root>/instance.profile.yaml when it exists
 *  (the consumer's root, defaulting to the CWD), else no file (the hub
 *  default). A DECLARED-but-missing file fails the boot — a misdeclared
 *  deployment must never silently boot as the hub. */
export function resolveNodeProfilePath(env: NodeJS.ProcessEnv = process.env, root: string = process.cwd()): string | null {
  const declared = env.INSTANCE_PROFILE
  if (declared) {
    const path = isAbsolute(declared) ? declared : resolve(process.cwd(), declared)
    if (!existsSync(path)) {
      throw new Error(`instance profile: INSTANCE_PROFILE points at ${path}, which does not exist`)
    }
    return path
  }
  const defaultPath = join(root, 'instance.profile.yaml')
  return existsSync(defaultPath) ? defaultPath : null
}

/** Load, install, and return the effective profile (memoized per
 *  process). The SEED_DEMO_PERSONAS env flag forces the demo cast on
 *  for the ia/tl profiles (never off — the file's `demo_personas:
 *  false` still holds under the flag's absence). */
export function loadNodeInstanceProfile(options?: LoadNodeProfileOptions): InstanceProfile {
  if (loaded && !options?.force) return loaded
  const path = options?.path ?? resolveNodeProfilePath(process.env, options?.root)
  const text = path === null ? undefined : readFileSync(path, 'utf-8')
  const demoEnv = process.env.SEED_DEMO_PERSONAS
  const profile = parseInstanceProfile(text, {
    demoPersonas: demoEnv === 'true' || demoEnv === '1' ? true : undefined,
  })
  installInstanceProfile(profile)
  loaded = profile
  return profile
}
