// ═══════════════════════════════════════════════════════════════════
// The stub mail provider (TODO.identity/09) — a tiny Resend-shaped
// HTTPS receiver for the tests, NO external dependency, node:http only
// (the stub-github.ts doctrine):
//
//   POST <any path> — captures the JSON body ({ from, to, subject,
//        text, html }) plus the authorization header, then answers 200
//        with a stub id. When the fixture declares `expectedKey`, a
//        wrong-or-missing Bearer key answers a provider-shaped 401 —
//        the platform's key handling is exercised, never assumed.
//
// One server plays the whole provider: the tests point MAIL_PROVIDER_URL
// at `${baseUrl}/emails` and read the captured messages back.
// ═══════════════════════════════════════════════════════════════════

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http'

export interface CapturedMail {
  from?: string
  to?: string
  subject?: string
  text?: string
  html?: string
  /** The request's authorization header (the key check's evidence). */
  authorization: string | null
}

export interface StubMailer {
  /** The base URL (no trailing slash); the provider path is the
   *  platform's MAIL_PROVIDER_URL value (`${baseUrl}/emails`). */
  baseUrl: string
  port: number
  /** Every captured message, in arrival order. */
  messages: CapturedMail[]
  reset(): void
  close(): Promise<void>
}

export async function startStubMailer(opts: { expectedKey?: string; port?: number } = {}): Promise<StubMailer> {
  const messages: CapturedMail[] = []

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      if (req.method !== 'POST') {
        res.writeHead(405).end()
        return
      }
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(chunk as Buffer)
      let body: Record<string, unknown> = {}
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>
      } catch {
        res.writeHead(400, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ message: 'invalid JSON' }))
        return
      }
      const authorization = req.headers.authorization ?? null
      if (opts.expectedKey && authorization !== `Bearer ${opts.expectedKey}`) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ message: 'API key is invalid' }))
        return
      }
      messages.push({ ...body, authorization } as CapturedMail)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ id: `stub-${messages.length}` }))
    })()
  })

  await new Promise<void>((resolveListen) => server.listen(opts.port ?? 0, '127.0.0.1', resolveListen))
  const port = (server.address() as { port: number }).port
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    port,
    messages,
    reset: () => { messages.length = 0 },
    close: () => new Promise<void>((resolveClose) => server.close(() => resolveClose())),
  }
}
