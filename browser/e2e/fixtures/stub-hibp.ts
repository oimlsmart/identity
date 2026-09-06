// ─────────────────────────────────────────────────────────────────────
// The HIBP range-API stub (TODO.identity-sso/04 slice B's e2e seam):
// the Pwned-Passwords-shaped endpoint the OP's breached-password check
// queries (server/auth/op/hibp.ts) — GET /{prefix5} answers the
// SUFFIX:count lines (CRLF, the real API's shape). The corpus is the
// test's live state: a suffix in `corpus` answers breached; `down`
// destroys every request's socket (the UNREACHABLE posture — the
// connection error the accept-and-recheck half rides). `hits` counts
// the queries (the no-marker-no-query pin).
//
// The check is k-anonymous by construction: the stub never sees a
// password, only the five-character prefix (and it ignores even that).
// ─────────────────────────────────────────────────────────────────────

import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

export interface StubHibp {
  baseUrl: string
  /** The query count (mutated by the handler — read it live). */
  hits: number
  /** true = unreachable: every request's socket is destroyed. */
  down: boolean
  /** The live corpus: SHA-1 suffixes (uppercase hex, post-prefix) that answer breached. */
  corpus: Set<string>
  close(): Promise<void>
}

export async function startStubHibp(opts: { port: number }): Promise<StubHibp> {
  const stub: StubHibp = {
    baseUrl: '',
    hits: 0,
    down: false,
    corpus: new Set<string>(),
    close: () => new Promise<void>((resolve) => { server.close(() => resolve()) }),
  }
  const server: Server = createServer((req, res) => {
    stub.hits += 1
    if (stub.down) {
      req.socket.destroy()
      return
    }
    const body = [...stub.corpus].map(s => `${s}:137`).join('\r\n')
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(body ? `${body}\r\n` : '')
  })
  await new Promise<void>((resolve) => server.listen(opts.port, '127.0.0.1', resolve))
  stub.baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  return stub
}
