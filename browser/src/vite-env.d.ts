/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

// The Cloudflare deployment: the workerd env's binding surface
// (wrangler.toml is the authoritative declaration; this augmentation
// types `cloudflare:workers`' env for the API endpoint shims and the
// worker composition root). Hand-maintained to stay inside the existing
// tsconfig.
declare namespace Cloudflare {
  interface Env {
    /** The D1 store binding (the account registry). */
    DB: import('@cloudflare/workers-types').D1Database
    /** The account-avatar uploads' R2 binding (unbound = the honest 503). */
    BLOBS?: import('@cloudflare/workers-types').R2Bucket
    /** The worker's static-asset binding. */
    ASSETS?: import('@cloudflare/workers-types').Fetcher
    /** 'server' = the shared entity store profile (see /api/config). */
    ENTITY_BACKEND?: string
    NODE_ENV?: string
  }
}

// workerd's env module. Declared here because the workers-types
// package's own ambient declaration does not register through the
// type-only imports this project uses; the Cloudflare adapter
// auto-externalizes the import and workerd resolves it at runtime.
declare module 'cloudflare:workers' {
  export const env: Cloudflare.Env
}
