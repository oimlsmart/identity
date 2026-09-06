import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// The unit suites (src/__tests__): the OP domain modules + routers
// proven in-process over temp SQLite stores. No app build config is
// involved (astro.config.mjs is the only app config); the vue plugin
// stays for the .vue mounts the account-console suite performs.
export default defineConfig({
  plugins: [vue()],
  server: {
    fs: {
      // Two levels up: the e2e fixtures + temp stacks the suites boot
      // outside the project root (the kernel itself comes from npm as a
      // plain node_modules directory — TODO.repos/01).
      allow: ['..', '../..'],
    },
  },
  test: {
    env: {
      // TODO.identity-sso/04 slice B: the breached-password check's corpus
      // is DISABLED across the unit suites (no test here hits the live
      // network; the check's own pins — id-password-breach.test.ts —
      // declare their stub endpoint in-file, overriding this).
      HIBP_RANGE_URL: 'off',
    },
  },
})
