// ═══════════════════════════════════════════════════════════════════
// The client branding accessor, identity-service shape: the runtime
// brand, resolved ONCE from /api/config (the `branding` key — the
// server projects the instance profile's branding section over the
// identity defaults), cached module-level. A failed probe keeps the
// default honestly.
//
// The identity service's brand surface is deliberately narrow: the
// product name, the logos, an optional login tagline and support URL.
// No theme overrides, no favicon/manifest swaps — the shell's static
// head already carries the service's own assets.
// ═══════════════════════════════════════════════════════════════════

import { computed, shallowRef, type ComputedRef } from 'vue'

export interface IdentityBranding {
  productName: string
  shortName: string
  /** Horizontal lockup: the header/login surfaces. */
  logoLight: string
  logoDark: string
  /** The compact mark. */
  markLight: string
  markDark: string
  loginTagline?: string
  supportUrl?: string
}

/** The default brand — the identity service's own. */
export const DEFAULT_BRANDING: IdentityBranding = {
  productName: 'OIML SMART Identity',
  shortName: 'OIML SMART Identity',
  logoLight: '/oiml-logo-light.svg',
  logoDark: '/oiml-logo-dark.svg',
  markLight: '/oiml-logo-cs-light.svg',
  markDark: '/oiml-logo-cs-dark.svg',
}

// shallowRef: the brand is always REPLACED wholesale (never mutated).
const serverBrand = shallowRef<IdentityBranding | null>(null)
let probed = false
let inflight: Promise<IdentityBranding> | null = null

/** The reactive brand for components: `const { branding } = useBranding()`. */
export function useBranding(): { branding: ComputedRef<IdentityBranding> } {
  return { branding: computed(() => serverBrand.value ?? DEFAULT_BRANDING) }
}

/** The synchronous read (non-reactive contexts — tests). */
export function currentBranding(): IdentityBranding {
  return serverBrand.value ?? DEFAULT_BRANDING
}

/** Resolve the instance brand from /api/config once (probed once,
 *  inflight-deduped) and cache. Never rejects: any failure leaves the
 *  default brand in place. */
export function resolveBranding(): Promise<IdentityBranding> {
  if (probed) return Promise.resolve(currentBranding())
  if (inflight) return inflight
  inflight = (async () => {
    try {
      const res = await fetch('/api/config', { credentials: 'include' })
      if (res.ok) {
        const config = (await res.json()) as { branding?: Partial<IdentityBranding> }
        if (config?.branding) serverBrand.value = { ...DEFAULT_BRANDING, ...config.branding }
      }
    } catch {
      // The probe failed — the default brand stands.
    } finally {
      probed = true
      inflight = null
    }
    return currentBranding()
  })()
  return inflight
}

/** Test seam: force the brand (unit tests never fetch). Null re-arms
 *  the probe and restores the default brand. */
export function setBrandingForTest(branding: IdentityBranding | null): void {
  inflight = null
  probed = branding !== null
  serverBrand.value = branding
}
