// ═══════════════════════════════════════════════════════════════════
// The instance's effective RBAC map (TODO.federation/12; extracted into
// the platform-server kernel, TODO.identity-extract/01).
//
// Resolution order for the instance's map:
//   1. an INSTALLED map (rbac/node.ts reads INSTANCE_RBAC_JSON or
//      the INSTANCE_PROFILE file's `rbac:` section at boot — the node
//      posture; the composition root installs through installRbacMap);
//   2. the INSTANCE_RBAC_JSON env var (any runtime — the Worker's
//      carrier, read per request through hono's env seam);
//   3. the shipped DEFAULT (vocab/rbac.ts — the hub profile).
//
// The write gate that ENFORCES the map on entity writes (the
// state-machine/permission computation over the program's data) stays
// with the platform (browser/server/rbac.ts) — it imports the program's
// generated state machines, which are not kernel content.
//
// WORKER-SAFE: no node built-ins (the file-reading half is
// rbac/node.ts).
// ═══════════════════════════════════════════════════════════════════

import {
  DEFAULT_ROLE_PERMISSIONS,
  resolveRolePermissions,
  type RolePermissionMap,
} from './vocab/rbac'

// ── The instance's effective map ─────────────────────────────────────

let installed: RolePermissionMap | null = null
/** Composition roots install the resolved map (node: server/index.ts
 *  via rbac/node.ts). Passing null restores env/default resolution —
 *  the tests' reset lever. */
export function installRbacMap(map: RolePermissionMap | null): void {
  installed = map
}

// The env-var parse is memoized per JSON string (the Worker resolves it
// per request; the string is deployment-static).
let envCache: { json: string; map: RolePermissionMap } | null = null

/** The instance's effective role → permission map. `env` is hono's
 *  runtimeEnv(c) at the route (process.env on node, the binding on the
 *  Worker) — may be omitted where no env is in scope. */
export function effectiveRbacMap(env?: Record<string, string | undefined>): RolePermissionMap {
  if (installed) return installed
  const json = env?.INSTANCE_RBAC_JSON
  if (json) {
    if (envCache?.json !== json) envCache = { json, map: resolveRolePermissions(JSON.parse(json)) }
    return envCache!.map
  }
  return DEFAULT_ROLE_PERMISSIONS
}
