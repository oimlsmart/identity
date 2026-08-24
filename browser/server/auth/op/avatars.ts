// ═══════════════════════════════════════════════════════════════════
// The account avatar doctrine (the account console's upload) — the
// limits and the byte-level checks, one module so the route and the
// tests (and the docs) cite the same numbers:
//
//   - SIZE: an avatar is a profile picture, never an archive — the cap
//     is 2 MiB (AVATAR_MAX_BYTES overrides for a deployment; the
//     document-store default of 25 MiB, routes/blobs.ts, is deliberately
//     NOT inherited — photographs of seals and spec sheets are not
//     profile pictures);
//   - TYPE: an allowlist of the four raster formats a browser renders
//     as an inert <img> (PNG, JPEG, WebP, GIF). SVG is EXCLUDED on
//     purpose: an SVG can carry script, and same-origin image serving
//     must never become an HTML/script channel;
//   - BYTES, NOT LABELS: the declared Content-Type only shortlists the
//     expectation — the stored bytes are sniffed (the magic prefixes
//     below) and must MATCH the declaration; a mislabeled payload is
//     refused, never stored.
//
// The blobs themselves ride the document-store seam (server/blobs.ts's
// BlobStore: R2 on the Worker, disk on node) under the `avatars/<account
// id>/avatar.<ext>` keys; a deployment without a blob store answers the
// honest 503 (the console hides the upload then — GET /api/op/account
// carries the feature flag).
//
// THE PUBLIC READ SIDE (routes/op.ts's GET /op/avatar/<account id> — the
// OIDC `picture` claim's target): an avatar is SEMI-PUBLIC by convention
// (the GitHub-avatars pattern — an RP renders it from a cross-origin
// <img>, so the serve needs no session). The stored upload serves with
// its real content type + a short public cache; a known account without
// an upload answers the GENERATED INITIALS (avatarInitials +
// initialsAvatarSvg — the console's own fallback, served), never a
// broken image; an unknown (or erased) account answers the plain 404.
// The initials SVG is server-GENERATED, not stored user bytes: the
// upload doctrine's SVG exclusion is untouched (the read side serves it
// with nosniff + a deny-all CSP so it can never become a script channel
// even on direct navigation).
//
// WORKER-SAFE: no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { blobKey } from '../../blobs'

/** The default upload cap: 2 MiB. AVATAR_MAX_BYTES overrides. */
export const AVATAR_MAX_BYTES_DEFAULT = 2 * 1024 * 1024

/** The allowlisted content types and their blob-key extensions. */
export const AVATAR_TYPES: Record<string, { ext: string }> = {
  'image/png': { ext: 'png' },
  'image/jpeg': { ext: 'jpg' },
  'image/webp': { ext: 'webp' },
  'image/gif': { ext: 'gif' },
}

/** The magic-prefix check per allowlisted type. */
const MAGIC: Record<string, number[]> = {
  'image/png': [0x89, 0x50, 0x4e, 0x47], // ‰PNG
  'image/jpeg': [0xff, 0xd8, 0xff],
  'image/gif': [0x47, 0x49, 0x46, 0x38], // GIF8
  // RIFF....WEBP — checked by sniffAvatar's two-window rule below.
  'image/webp': [],
}

/** Sniff the payload's real type from its magic bytes. Answers the
 *  allowlisted content type, or null when the bytes match none. */
export function sniffAvatar(data: ArrayBuffer): string | null {
  const bytes = new Uint8Array(data)
  for (const [type, prefix] of Object.entries(MAGIC)) {
    if (type === 'image/webp') continue
    if (bytes.length >= prefix.length && prefix.every((b, i) => bytes[i] === b)) return type
  }
  // WebP: 'RIFF' + the 4-byte size + 'WEBP'.
  if (
    bytes.length >= 12
    && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46
    && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) return 'image/webp'
  return null
}

/** Resolve the effective upload cap from the env (an unparsable or
 *  non-positive value falls back to the default, honestly). */
export function avatarMaxBytes(env: Record<string, unknown>): number {
  const raw = env.AVATAR_MAX_BYTES
  const parsed = Number(typeof raw === 'string' ? raw : '')
  return Number.isInteger(parsed) && parsed > 0 ? parsed : AVATAR_MAX_BYTES_DEFAULT
}

/** Every blob key the account's avatar can live under (one per
 *  allowlisted extension — the upload deletes the siblings, so at most
 *  one exists at a time). */
export function avatarKeys(userId: string): string[] {
  return Object.values(AVATAR_TYPES).map(t => blobKey('avatars', userId, `avatar.${t.ext}`))
}

/** The account's avatar key for a content type (validated — the caller
 *  checked the type against AVATAR_TYPES). */
export function avatarKey(userId: string, contentType: string): string {
  return blobKey('avatars', userId, `avatar.${AVATAR_TYPES[contentType]!.ext}`)
}

// ── the public read side (GET /op/avatar/<account id>) ───────────────

/** The public route's cache posture: short and PUBLIC (the RP's <img>
 *  fleet may share it) — an upload swap or a rename settles within five
 *  minutes, the same concession every avatar CDN makes. */
export const AVATAR_PUBLIC_CACHE = 'public, max-age=300'

/** The initials the console falls back to (account.vue's rule, mirrored
 *  exactly so the served fallback renders what the console would):
 *  the first letter of the first and last name words, uppercased, '?'
 *  when the name is empty. */
export function avatarInitials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  return ((parts[0]?.[0] ?? '') + (parts[parts.length - 1]?.[0] ?? '')).toUpperCase() || '?'
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** The generated-initials fallback avatar: a 96×96 circle in the brand
 *  palette (the console chip's light scheme — a light disc reads on a
 *  dark page too), the account's initials centered. INERT by
 *  construction: fixed markup, the initials XML-escaped, no scripts, no
 *  external references. */
export function initialsAvatarSvg(name: string): string {
  const initials = escapeXml(avatarInitials(name))
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" width="96" height="96">`
    + `<circle cx="48" cy="48" r="48" fill="#dde9fc"/>`
    + `<text x="48" y="48" text-anchor="middle" dominant-baseline="central" `
    + `font-family="ui-sans-serif, system-ui, sans-serif" font-size="36" font-weight="600" fill="#003a78">${initials}</text>`
    + `</svg>`
}
