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
      // The file:-linked kernel resolves to its realpath under
      // ../x/oimlsmart/smart — one level up from this project root.
      allow: ['..', '../..'],
    },
  },
  test: {},
})
