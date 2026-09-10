// ═══════════════════════════════════════════════════════════════════
// The NODE half of the RBAC map resolution (TODO.federation/12): reads
// the instance's role → permission map from the environment at boot.
//
// Carriers, in precedence order:
//   1. INSTANCE_RBAC_JSON — the map as a JSON object
//      (`{"case_officer": ["application.review", …], …}`); replaces the
//      shipped default WHOLESALE (the profile owns its role model);
//   2. INSTANCE_PROFILE — the deployment profile file
//      (TODO.federation/01's carrier); its top-level `rbac:` section is
//      the map. This is the ADDITIVE reader: when fed-01's profile
//      loader lands it resolves the section itself and installs through
//      installRbacMap — same seam, one semantics
//      (resolveRolePermissions).
//
// NODE-ONLY: fs + js-yaml. The Worker reads INSTANCE_RBAC_JSON from its
// bindings through effectiveRbacMap(env) instead (server/rbac.ts).
// ═══════════════════════════════════════════════════════════════════

import { readFileSync } from 'fs'
import yaml from 'js-yaml'
import { resolveRolePermissions, type RolePermissionMap } from '../vocab/rbac'

/** Resolve the instance's RBAC map from the node environment. Returns
 *  null when no carrier is set — the shipped default then applies (the
 *  hub profile; effectiveRbacMap falls through to it). Throws honestly
 *  on an unreadable profile or an invalid map (a deployment bug, never
 *  silently defaulted). */
export function loadNodeRbacMap(env: NodeJS.ProcessEnv = process.env): RolePermissionMap | null {
  const json = env.INSTANCE_RBAC_JSON
  if (json) {
    return resolveRolePermissions(JSON.parse(json))
  }
  const profilePath = env.INSTANCE_PROFILE
  if (profilePath) {
    const profile = yaml.load(readFileSync(profilePath, 'utf-8')) as { rbac?: unknown } | null
    if (profile && profile.rbac !== undefined && profile.rbac !== null) {
      return resolveRolePermissions(profile.rbac)
    }
  }
  return null
}
