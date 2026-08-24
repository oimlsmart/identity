// ═══════════════════════════════════════════════════════════════════
// The SSO home's launch metadata (the post-login launcher, the spec:
// TODO.identity-extract/02a's "post-login landing") — the ONE validator
// every writer of the client registry's launch columns shares: the
// bootstrap seed (./registry.ts) and the registry's admin surface
// (routes/op.ts) refuse a malformed card the same way, loudly, at write
// time, never at render.
//
// The card carries: the launch URL (the service's sign-in start — the
// live OP session lets the user straight in), the icon glyph's name
// (the small named set below — the launcher's LaunchIcon component owns
// the glyphs), the one-line description, and the visibility rule for an
// account the computed role set does not admit ('roles' hides the card,
// 'request' shows it with the plain request-access state, 'open' never
// gates — the service admits every signed-in account).
//
// WORKER-SAFE: pure functions, no I/O.
// ═══════════════════════════════════════════════════════════════════

import type { OidcClientLaunch } from '@oimlsmart/platform-server/store'

/** The named icon set. The launcher's LaunchIcon.vue owns the glyphs;
 *  a name outside this set is a configuration bug, refused at write. */
export const LAUNCH_ICONS = ['grid', 'monitor', 'scale', 'flask', 'chat', 'external'] as const

export const LAUNCH_VISIBILITIES: readonly OidcClientLaunch['visibility'][] = ['roles', 'request', 'open']

/** The wire shape (the seed entry's + the registry API's `launch`). */
export interface LaunchInput {
  url?: unknown
  icon?: unknown
  description?: unknown
  visibility?: unknown
}

/** Validate a launch-metadata write. Answers the normalized row, or the
 *  refusal's reason (the callers shape it into their own error answer —
 *  the seed throws, the API answers 400). */
export function validateLaunch(input: LaunchInput): { launch: OidcClientLaunch | null; error: string | null } {
  if (typeof input.url !== 'string' || !input.url.trim()) {
    return { launch: null, error: 'launch.url is required (the service’s sign-in start)' }
  }
  const url = input.url.trim()
  let parsed: URL
  try { parsed = new URL(url) } catch {
    return { launch: null, error: `launch.url ${JSON.stringify(url)} is not an absolute URL` }
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { launch: null, error: 'launch.url must be an http(s) URL' }
  }
  if (input.icon !== undefined && input.icon !== null && (typeof input.icon !== 'string' || !(LAUNCH_ICONS as readonly string[]).includes(input.icon))) {
    return { launch: null, error: `launch.icon must be one of: ${LAUNCH_ICONS.join(', ')}` }
  }
  if (input.description !== undefined && input.description !== null && typeof input.description !== 'string') {
    return { launch: null, error: 'launch.description must be a string' }
  }
  if (input.visibility !== undefined && !LAUNCH_VISIBILITIES.includes(input.visibility as OidcClientLaunch['visibility'])) {
    return { launch: null, error: `launch.visibility must be one of: ${LAUNCH_VISIBILITIES.join(', ')}` }
  }
  return {
    launch: {
      url,
      icon: typeof input.icon === 'string' ? input.icon : null,
      description: typeof input.description === 'string' && input.description.trim() ? input.description.trim() : null,
      visibility: (input.visibility as OidcClientLaunch['visibility'] | undefined) ?? 'roles',
    },
    error: null,
  }
}
