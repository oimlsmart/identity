// ═══════════════════════════════════════════════════════════════════
// TODO.sota/07.4 — the AVATAR SERVE module, extracted from op.ts as
// the first proof of the domain-model split (the pure refactor; the
// golden + the suite are the proof — zero behavior change).
//
// GET /op/avatar/:id — the PUBLIC read side of the account's avatar
// (the GitHub-avatars pattern: an avatar is semi-public by convention,
// so the RP's cross-origin <img> needs no session). This is the URL
// the `picture` claim names. The doctrine (auth/op/avatars.ts):
//
//   - the account resolves FIRST: an unknown or ERASED account answers
//     the plain 404 (the erasure's promise is stronger than a stray
//     surviving blob — the account is gone, nothing serves);
//   - the stored upload serves with its real content type, nosniff,
//     and a short PUBLIC cache;
//   - a KNOWN account without an upload (or a deployment with no blob
//     store bound) answers the GENERATED-INITIALS fallback — the
//     console's own fallback, served — so the <img> never breaks;
//   - NEVER an error page: every answer is an image or a small JSON.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { getStore } from '../store'
import { getBlobStore } from '../blobs'
import { avatarKeys, AVATAR_PUBLIC_CACHE, initialsAvatarSvg } from '../auth/op/avatars'

export function createOpAvatarServeRouter(): Hono {
  const router = new Hono()

  router.get('/op/avatar/:id', async (c: Context) => {
    const userId = c.req.param('id') ?? ''
    const user = await getStore().getUserById(userId)
    if (!user || user.provider === 'erased') {
      return c.json({ error: 'not found' }, 404)
    }
    const blobs = getBlobStore()
    if (blobs) {
      for (const key of avatarKeys(userId)) {
        const obj = await blobs.get(key)
        if (!obj) continue
        c.header('content-type', obj.contentType ?? 'application/octet-stream')
        c.header('content-length', String(obj.size))
        c.header('x-content-type-options', 'nosniff')
        c.header('cache-control', AVATAR_PUBLIC_CACHE)
        return c.body(obj.data)
      }
    }
    c.header('content-type', 'image/svg+xml')
    // The served SVG is server-generated and inert; the deny-all CSP is
    // the belt-and-suspenders for direct navigation (an image channel
    // never becomes a script channel — the avatar doctrine's rule).
    c.header('content-security-policy', "default-src 'none'")
    c.header('x-content-type-options', 'nosniff')
    c.header('cache-control', AVATAR_PUBLIC_CACHE)
    return c.body(initialsAvatarSvg(user.name ?? ''))
  })

  return router
}
