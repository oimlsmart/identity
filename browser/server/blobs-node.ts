// ═══════════════════════════════════════════════════════════════════
// The blob store, node entry (TODO.adoption/03): the local-disk adapter
// — node:fs behind the worker-safe BlobStore contract (blobs.ts), the
// same split branding-node.ts / profile-node.ts use. The node
// composition root (server/index.ts) installs it at boot:
//
//   BLOBS_DIR=/var/lib/oiml-smart/blobs   (default: browser/data/blobs)
//   BLOBS_DISABLED=true                   (the explicit unavailable
//                                          posture — the routes 503 and
//                                          the client records file names
//                                          only, honestly)
//
// Layout on disk: <root>/<key> holds the bytes (the key's three segments
// are validated safe by blobs.ts before they reach this adapter) and
// <key>.meta.json the sidecar ({ contentType }) — R2's httpMetadata
// counterpart. Writes go through a temp file + rename so a crashed write
// never leaves a half-written blob under the final name.
// ═══════════════════════════════════════════════════════════════════

import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseBlobKey, type BlobStore } from './blobs'

/** The default blob root: browser/data/blobs (this module lives in
 *  browser/server/ — resolved from the module, never the cwd, so the
 *  answer is the same from tsx watch, the vitest worker, or a script). */
export function defaultBlobsRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '../data/blobs')
}

/** The configured blob root for the node posture: BLOBS_DIR wins, the
 *  default otherwise. BLOBS_DISABLED=true answers null — the caller
 *  installs the unavailable posture (no adapter) instead. */
export function nodeBlobsRoot(env: NodeJS.ProcessEnv = process.env): string | null {
  if (env.BLOBS_DISABLED === 'true') return null
  return env.BLOBS_DIR ? resolve(env.BLOBS_DIR) : defaultBlobsRoot()
}

export function diskBlobStore(root: string): BlobStore {
  const pathFor = (key: string): string => {
    // parseBlobKey is the traversal guard: a malformed key (a `..`
    // segment, a separator) never becomes a path.
    const parsed = parseBlobKey(key)
    if (!parsed) throw new Error(`malformed blob key: ${JSON.stringify(key)}`)
    return join(root, parsed.ownerStore, parsed.ownerId, parsed.blobId)
  }

  return {
    async put(key, data, contentType) {
      const file = pathFor(key)
      await mkdir(dirname(file), { recursive: true })
      const tmp = `${file}.tmp-${crypto.randomUUID()}`
      await writeFile(tmp, Buffer.from(data))
      await rename(tmp, file)
      const meta = contentType ? JSON.stringify({ contentType }) : '{}'
      await writeFile(`${file}.meta.json`, meta, 'utf-8')
    },
    async get(key) {
      const file = pathFor(key)
      let bytes: Buffer
      try {
        bytes = await readFile(file)
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null
        throw e
      }
      let contentType: string | null = null
      try {
        const meta = JSON.parse(await readFile(`${file}.meta.json`, 'utf-8')) as { contentType?: string }
        contentType = meta.contentType ?? null
      } catch { /* no sidecar (or corrupt) — the blob still serves, typeless */ }
      return {
        data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
        contentType,
        size: bytes.byteLength,
      }
    },
    async delete(key) {
      const file = pathFor(key)
      await rm(file, { force: true })
      await rm(`${file}.meta.json`, { force: true })
    },
  }
}
