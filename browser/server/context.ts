// ═══════════════════════════════════════════════════════════════════
// The kernel's request-context type (TODO.identity-extract/01).
//
// The kernel is consumed through a file: link in the monorepo and from
// npm by the identity service; in BOTH shapes its sources resolve hono
// from a DIFFERENT module instance than the consuming app's. hono's
// Context/HonoRequest carry a `unique symbol` brand (GET_MATCH_RESULT),
// so the two instances' Context types are nominally incompatible — a
// kernel helper typed on hono's Context would reject the app's contexts
// at the seam (and a tsconfig-paths type alias is not an answer: tsx
// applies tsconfig paths at RUNTIME and would resolve the value import
// to a .d.ts).
//
// So the kernel never names hono's Context in a public signature. It
// names THIS: the structural slice it actually touches (the request's
// header read + the env slot). hono's Context satisfies it structurally
// (HonoRequest.header has the `header(name: string)` overload); the
// hono boundary inside each helper holds one documented cast.
// ═══════════════════════════════════════════════════════════════════

export interface KernelContext {
  req: {
    header(name: string): string | undefined
    /** hono's HonoRequest.raw — the cookie helper reads the Cookie
     *  header off the raw request. */
    raw: Request
  }
  /** hono's Context.env (process.env on node, the bindings on the
   *  Worker) — read through hono/adapter's env() at the seam. */
  env?: unknown
}
