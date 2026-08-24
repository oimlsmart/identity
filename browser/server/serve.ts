import { serve } from '@hono/node-server'
import { config } from 'dotenv'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// The env surface composes FIRST (.env.local), and only then does the
// composition root (./index) boot, so its import-time resolutions read
// the COMPLETE env. (A static `import app from './index'` would hoist
// the boot ABOVE dotenv.)
config({ path: '.env.local' })

// The identity service's node posture boots the identity profile by
// default: the kernel's profile loader falls back to the hub default
// without INSTANCE_PROFILE, and the hub 404s every OP path. Declared
// always wins (the e2e stacks declare their fixture).
process.env.INSTANCE_PROFILE ||= join(dirname(fileURLToPath(import.meta.url)), 'instance.profile.dev.yaml')

const { default: app } = await import('./index')

const port = Number(process.env.PORT || 3190)

serve({ fetch: app.fetch, port }, () => {
  console.log(`OIML SMART identity server running on http://localhost:${port}`)
})
