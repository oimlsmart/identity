// ═══════════════════════════════════════════════════════════════════
// The shared identity vocabulary (TODO.identity-extract/01, the map:
// PROGRESS/41 §2): the role model, the role → permission map, and the
// action-permission catalog — the three plain-TS modules the browser
// bundle, the node server and the Cloudflare Worker all import.
//
// ISOMORPHIC: no Vue, no node built-ins, no side effects.
// ═══════════════════════════════════════════════════════════════════

export * from './roles'
export * from './rbac'
export * from './permissions'
