import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    fs: {
      allow: ['..', '../..'],
    },
  },
  test: {
    include: ['e2e/**/*.e2e.ts'],
    // The identity legs boot their own stacks (port-isolated, one SQLite
    // file per leg) but share the host's CPU: sequential files, matching
    // the smart repo's suite discipline under dev-server contention.
    fileParallelism: false,
    // Cold vite on-demand compiles can take 15-30 s under dev; the
    // legs' waits are sized accordingly, so the per-test budget must
    // cover several of them.
    testTimeout: 240_000,
    hookTimeout: 120_000,
  },
})
