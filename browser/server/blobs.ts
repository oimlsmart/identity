// ═══════════════════════════════════════════════════════════════════
// The blob store seam (TODO.adoption/03 — the document store).
//
// The workflow's documents (spec sheets, ER PDFs, sample photographs,
// report attachments, certificate annexes, agreement documents) are real
// BYTES, not file-name-only records. The routes never talk to a storage
// driver directly: they go through the BlobStore contract, with two
// adapters chosen by BINDING PRESENCE at the composition root — the same
// profile pattern the entity store uses (db/backend.ts):
//
//   - R2 (Cloudflare Workers): the wrangler `BLOBS` r2_buckets binding —
//     the Worker middleware installs r2BlobStore(env.BLOBS) per request;
//   - local disk (node, dev + self-hosted): blobs-node.ts's
//     diskBlobStore (node:fs — the Worker bundle never imports it),
//     installed by server/index.ts at boot.
//
// Neither bound ⇒ the HONEST UNAVAILABLE posture: getBlobStore() answers
// null, the routes answer 503, and the client keeps the historical
// file-name-only recording (the DocumentRef carries the name, the bytes
// stay with the sender) — never a silent drop.
//
// The key discipline: a blob key is `<owner store>/<owner entity id>/<blob
// id>` — three safe-segments, the owner ALWAYS an entity row. Ownership
// is how the download gate resolves visibility (routes/blobs.ts): the
// entity's own org rules decide who reads the blob, and the entity must
// actually carry a reference naming the key (a guessed key under a
// readable entity answers 404).
//
// This module is WORKER-SAFE: no node built-ins anywhere.
// ═══════════════════════════════════════════════════════════════════

/** The minimal R2 bucket surface this seam consumes (a structural subset
 *  of @cloudflare/workers-types' R2Bucket — declared locally so the
 *  module carries no Cloudflare import on the node graph either). */
export interface R2BucketLike {
  put(key: string, value: ArrayBuffer | ArrayBufferView, options?: { httpMetadata?: { contentType?: string } }): Promise<unknown>
  get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; size: number; httpMetadata?: { contentType?: string } } | null>
  delete(key: string): Promise<void>
}

export interface BlobObject {
  data: ArrayBuffer
  contentType: string | null
  size: number
}

/** The async blob contract the routes consume. */
export interface BlobStore {
  put(key: string, data: ArrayBuffer, contentType: string | null): Promise<void>
  get(key: string): Promise<BlobObject | null>
  delete(key: string): Promise<void>
}

/** One key segment: letters, digits, and `-._~` only, STARTING with a
 *  letter or digit (so `.`/`..` never validate — no traversal, no
 *  dotfiles) — the disk adapter joins these. */
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,199}$/

/** Build + validate a blob key from its three segments. Throws on an
 *  unsafe segment — a malformed owner or blob id never reaches storage. */
export function blobKey(ownerStore: string, ownerId: string, blobId: string): string {
  for (const seg of [ownerStore, ownerId, blobId]) {
    if (!SEGMENT.test(seg)) throw new Error(`unsafe blob key segment: ${JSON.stringify(seg)}`)
  }
  return `${ownerStore}/${ownerId}/${blobId}`
}

/** Split a key back into its segments (null when malformed). */
export function parseBlobKey(key: string): { ownerStore: string; ownerId: string; blobId: string } | null {
  const parts = key.split('/')
  if (parts.length !== 3 || parts.some(p => !SEGMENT.test(p))) return null
  const [ownerStore, ownerId, blobId] = parts as [string, string, string]
  return { ownerStore, ownerId, blobId }
}

/** The SHA-256 hex digest of a payload (Web Crypto — worker-safe, node
 *  ≥ 19 exposes the same global). The upload route computes it over the
 *  received bytes; the DocumentRef carries it; downloads re-verify. */
export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

/** The R2 adapter. The bucket persists httpMetadata.contentType; reads
 *  return null when the key is absent (R2's honest miss). */
export function r2BlobStore(bucket: R2BucketLike): BlobStore {
  return {
    async put(key, data, contentType) {
      await bucket.put(key, data, contentType ? { httpMetadata: { contentType } } : undefined)
    },
    async get(key) {
      const obj = await bucket.get(key)
      if (!obj) return null
      return {
        data: await obj.arrayBuffer(),
        contentType: obj.httpMetadata?.contentType ?? null,
        size: obj.size,
      }
    },
    async delete(key) {
      await bucket.delete(key)
    },
  }
}

// ── the installed-store seam (mirrors db/backend.ts) ─────────────────

let current: BlobStore | null = null

/** The composition roots install the store exactly once per process /
 *  per request binding. NULL is a legitimate install: the explicit
 *  unavailable posture (a Worker without the BLOBS binding). */
export function installBlobStore(store: BlobStore | null): void {
  current = store
}

/** The installed store, or NULL — the honest unavailable posture. Unlike
 *  the entity store this never throws: a deployment without a blob
 *  backend is a supported configuration (file-name-only recording), so
 *  the routes translate null into a plain 503. */
export function getBlobStore(): BlobStore | null {
  return current
}

/** Test seam: re-arm the seam between cases. */
export function uninstallBlobStoreForTest(): void {
  current = null
}
