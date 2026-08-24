// ─────────────────────────────────────────────────────────────────────
// The avatar crop's geometry (src/lib/avatar-crop.ts), proven in-process:
// the cover-fit, the clamped pan (no blank edge can ever show), the
// center-anchored zoom, and the source rect the crop reads. Plus the
// client/server doctrine lock: the dialog's type allowlist MIRRORS the
// server's AVATAR_TYPES (server/auth/op/avatars.ts) — a drift here fails
// this suite before it can confuse a refusal.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import {
  AVATAR_ACCEPT_TYPES,
  clampOffset,
  cropSourceRect,
  fitScale,
  initialView,
  panBy,
  withScale,
  zoomAt,
  zoomPosition,
  ZOOM_RANGE,
  type CropView,
} from '../lib/avatar-crop'
import { AVATAR_TYPES } from '../../server/auth/op/avatars'

const VIEWPORT = 280

/** A landscape 640×320 image's opening view: cover-fit, centered. */
function landscapeView(): CropView {
  return initialView(640, 320, VIEWPORT)
}

describe('avatar-crop — the cover fit', () => {
  it('fitScale covers the square from the SHORT side', () => {
    expect(fitScale(640, 320, VIEWPORT)).toBeCloseTo(0.875)
    expect(fitScale(320, 640, VIEWPORT)).toBeCloseTo(0.875)
    expect(fitScale(280, 280, VIEWPORT)).toBe(1)
  })

  it('the initial view centers the cover-fit image', () => {
    const v = landscapeView()
    expect(v.scale).toBeCloseTo(0.875)
    // 640×0.875 = 560 wide → the overflow (280) splits evenly.
    expect(v.offsetX).toBeCloseTo(-140)
    expect(v.offsetY).toBe(0) // 320×0.875 = 280 = the viewport exactly
  })

  it('degenerate sizes never divide by zero', () => {
    expect(fitScale(0, 0, VIEWPORT)).toBe(1)
    expect(fitScale(640, 320, 0)).toBe(1)
  })
})

describe('avatar-crop — the pan clamps', () => {
  it('a drag beyond an edge clamps (no blank can ever show)', () => {
    const v = landscapeView()
    const right = panBy(v, 1000, 0) // the image follows the pointer right
    expect(right.offsetX).toBe(0)
    const left = panBy(v, -1000, 0)
    expect(left.offsetX).toBe(280 - 560) // the right edge pinned to the window
    expect(panBy(v, 0, 500).offsetY).toBe(0) // the exact-fit axis stays centered
    expect(panBy(v, 0, -500).offsetY).toBe(0)
  })

  it('an axis whose scaled size IS the viewport pins centered', () => {
    const v = clampOffset({ viewport: VIEWPORT, imageWidth: 280, imageHeight: 280, scale: 1, offsetX: 42, offsetY: -7 })
    expect(v.offsetX).toBe(0)
    expect(v.offsetY).toBe(0)
  })
})

describe('avatar-crop — the source rect', () => {
  it('a square image at the fit reads itself out whole', () => {
    const rect = cropSourceRect(initialView(280, 280, VIEWPORT))
    expect(rect).toEqual({ sx: 0, sy: 0, side: 280 })
  })

  it('the centered cover of a landscape image reads the middle square', () => {
    const rect = cropSourceRect(landscapeView())
    expect(rect.sx).toBeCloseTo(160)
    expect(rect.sy).toBe(0)
    expect(rect.side).toBeCloseTo(320)
    // …and the rect stays inside the image.
    expect(rect.sx + rect.side).toBeLessThanOrEqual(640)
  })

  it('the pan moves the rect and the clamp keeps it inside the image', () => {
    const rect = cropSourceRect(panBy(landscapeView(), -1000, 0))
    expect(rect.sx).toBeCloseTo(320)
    expect(rect.sx + rect.side).toBeCloseTo(640)
  })
})

describe('avatar-crop — the zoom', () => {
  it('zoomAt runs geometric from the fit to its ZOOM_RANGE multiple', () => {
    const fit = fitScale(640, 320, VIEWPORT)
    expect(zoomAt(fit, 0)).toBeCloseTo(fit)
    expect(zoomAt(fit, 1)).toBeCloseTo(fit * ZOOM_RANGE)
    expect(zoomAt(fit, -1)).toBeCloseTo(fit) // the slider clamps
    expect(zoomAt(fit, 2)).toBeCloseTo(fit * ZOOM_RANGE)
  })

  it('zoomPosition inverts zoomAt', () => {
    const fit = fitScale(640, 320, VIEWPORT)
    for (const t of [0, 0.25, 0.5, 0.75, 1]) {
      expect(zoomPosition(fit, zoomAt(fit, t))).toBeCloseTo(t)
    }
    expect(zoomPosition(fit, fit / 2)).toBe(0) // below the floor: the floor
  })

  it('withScale keeps the window center on the same image point', () => {
    const v = landscapeView()
    const before = cropSourceRect(v)
    const cxBefore = before.sx + before.side / 2
    const cyBefore = before.sy + before.side / 2
    const zoomed = withScale(v, v.scale * 2)
    const after = cropSourceRect(zoomed)
    expect(after.sx + after.side / 2).toBeCloseTo(cxBefore)
    expect(after.sy + after.side / 2).toBeCloseTo(cyBefore)
    expect(after.side).toBeCloseTo(before.side / 2)
    // …and the zoomed rect still sits inside the image.
    expect(after.sx).toBeGreaterThanOrEqual(0)
    expect(after.sy).toBeGreaterThanOrEqual(0)
  })

  it('zooming at the pinned edge re-clamps instead of showing blank', () => {
    const pinned = panBy(landscapeView(), -1000, 0)
    const zoomed = withScale(pinned, pinned.scale * 4)
    const rect = cropSourceRect(zoomed)
    expect(rect.sx).toBeGreaterThanOrEqual(0)
    expect(rect.sx + rect.side).toBeLessThanOrEqual(640 + 1e-9)
  })
})

describe('avatar-crop — the client/server doctrine lock', () => {
  it('the dialog allowlist mirrors the server AVATAR_TYPES keys', () => {
    expect([...AVATAR_ACCEPT_TYPES].sort()).toEqual(Object.keys(AVATAR_TYPES).sort())
  })
})
