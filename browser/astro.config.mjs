// @ts-check
// ═══════════════════════════════════════════════════════════════════
// Astro 7 config — the identity service's thin shell (the extraction
// map, smart's PROGRESS/41 §3): the site-shell design tokens + the vue
// plugin + the dev proxy for the OP/API paths. No data trees, no
// codegen plugins, no PWA: the service renders the OP's pages and
// nothing else.
//
// The adapter is a BUILD-TIME choice (the smart monorepo's posture):
// ADAPTER unset (dev, CI, the self-hosted posture) or
// ADAPTER=cloudflare (the Workers build — wrangler.toml +
// server/cloudflare.ts).
// ═══════════════════════════════════════════════════════════════════
import { defineConfig } from 'astro/config'
import vue from '@astrojs/vue'
import node from '@astrojs/node'
import cloudflare from '@astrojs/cloudflare'
import tailwindcss from '@tailwindcss/vite'

const isCloudflare = process.env.ADAPTER === 'cloudflare'

// The kernel comes from npm (TODO.repos/01): a real directory inside
// node_modules, so no fs.allow widening for a file:-linked realpath is
// needed anymore.

export default defineConfig({
  // Hybrid rendering: every shell carries `export const prerender =
  // true`; the OP endpoint shims (jwks.json, the discovery document,
  // the /api catch-all) are prerender=false and server-rendered.
  output: 'server',
  // Cloudflare: imageService passthrough — the service serves static
  // assets only, so the generated worker config stays free of an
  // Images binding nothing provisions.
  adapter: isCloudflare ? cloudflare({ imageService: 'passthrough' }) : node({ mode: 'standalone' }),
  // The Cloudflare posture carries no Astro-session KV driver (the
  // sessions are the D1 sessions table) — `false` keeps the adapter
  // from auto-enabling its KV session binding.
  ...(isCloudflare ? { session: false } : {}),
  outDir: './dist',
  server: {
    // The same port the smart monorepo's dev stack and the e2e suite use.
    port: 5190,
  },
  integrations: [
    vue({
      // Installs a vue-router instance into every island app so the page
      // components (useRoute/useRouter/<router-link>) work unmodified.
      appEntrypoint: '/src/astro/app-entrypoint',
    }),
  ],
  vite: {
    // The spawned e2e stacks boot a SECOND astro dev over this same
    // project root: VITE_CACHE_DIR isolates a stack's dep-optimizer
    // cache (the smart repo's two-stack lesson); unset keeps vite's
    // default untouched.
    ...(process.env.VITE_CACHE_DIR ? { cacheDir: process.env.VITE_CACHE_DIR } : {}),
    // The endpoint shims (src/pages/api/[...path].ts and friends) probe
    // the workerd env via `import('cloudflare:workers')`. Under the
    // Cloudflare adapter that scheme is the plugin's own; under the
    // node build it must stay an unresolved runtime import so the probe
    // can reject honestly.
    ...(isCloudflare ? {} : { ssr: { external: ['cloudflare:workers'] } }),
    plugins: [tailwindcss()],
    server: {
      strictPort: true,
      // The node posture's dev proxy: the OP/API paths → the tsx API
      // server. The Cloudflare posture serves them from INSIDE the
      // worker (the endpoint shims), so no proxy is installed there.
      // ONLY the API paths are forwarded: /op/consent and the other OP
      // pages stay with Astro (static routes win over the proxy).
      ...(isCloudflare ? {} : {
        proxy: {
          '/api': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          '/.well-known/openid-configuration': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          '/jwks.json': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          '/op/authorize': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          // The org key-resolution endpoint (TODO.trust-registry/01):
          // PUBLIC, anonymous — the verifiers fetch it cross-origin.
          '/op/keys': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          '/op/token': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          '/op/userinfo': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          '/op/avatar': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          // The whoami beacon (the static properties' account chips):
          // the OP session's minimal projection, CORS-gated — fetched
          // cross-origin with credentials.
          '/op/whoami': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
          '/op/upstream': {
            target: process.env.API_ORIGIN || 'http://localhost:3190',
            headers: { 'X-Forwarded-Host': process.env.DEV_PUBLIC_HOST || 'localhost:5190', 'X-Forwarded-Proto': 'http' },
          },
        },
      }),
    },
  },
})
