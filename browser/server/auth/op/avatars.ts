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
