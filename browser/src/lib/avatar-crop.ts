// ═══════════════════════════════════════════════════════════════════
// The avatar crop's pure geometry, split from the dialog's DOM/canvas
// plumbing (components/AvatarCropDialog.vue) so the unit suite proves
// the math in-process. The doctrine lives in server/auth/op/avatars.ts
// (the cap + the raster allowlist + the byte sniff); this module only
// MIRRORS the allowlist for the fast honest refusal — the server
// re-judges everything, the route is never trusted to fix the image.
//
// The model: a square viewport shows a window onto the scaled image
// (cover-fit at minimum zoom). The user drags (the offset moves the
// image under the window) and zooms (the scale grows). The crop reads
// the square source rect the window covers and renders it to a
// AVATAR_OUTPUT_SIZE px PNG: that blob IS the upload.
// ═══════════════════════════════════════════════════════════════════

/** The crop output: a square PNG of this side. 256 px stays crisp at
 *  every render size the service uses (the console's 48 px, the header's
 *  20 px) and lands at a few tens of KB — far under the server's cap. */
export const AVATAR_OUTPUT_SIZE = 256
export const AVATAR_OUTPUT_TYPE = 'image/png'

/** The client-side mirror of the server's raster allowlist
 *  (server/auth/op/avatars.ts's AVATAR_TYPES keys — the unit suite
 *  cross-checks the mirror against them). The refusal is the fast
 *  honest path; the server sniffs the bytes regardless. */
export const AVATAR_ACCEPT_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'] as const

/** The furthest zoom: this multiple of the cover-fit scale. */
export const ZOOM_RANGE = 8

export interface CropView {
  /** The square viewport's side, CSS px. */
  viewport: number
  /** The source image's natural size, px. */
  imageWidth: number
  imageHeight: number
  /** Viewport px per image px (the zoom; >= fitScale). */
  scale: number
  /** The image's top-left corner in viewport coordinates (<= 0). */
  offsetX: number
  offsetY: number
}

/** The cover-fit scale: the smallest scale at which the image fills the
 *  square viewport (the zoom floor). */
export function fitScale(imageWidth: number, imageHeight: number, viewport: number): number {
  if (imageWidth <= 0 || imageHeight <= 0 || viewport <= 0) return 1
  return viewport / Math.min(imageWidth, imageHeight)
}

/** The zoom for a slider position t in [0, 1]: geometric between the
 *  cover-fit floor and its ZOOM_RANGE multiple (a linear slider over a
 *  geometric range keeps small zooms fine-grained). */
export function zoomAt(fit: number, t: number): number {
  const clamped = Math.min(1, Math.max(0, t))
  return fit * Math.pow(ZOOM_RANGE, clamped)
}

/** The slider position for a scale (zoomAt's inverse). */
export function zoomPosition(fit: number, scale: number): number {
  if (fit <= 0 || scale <= fit) return 0
  return Math.min(1, Math.log(scale / fit) / Math.log(ZOOM_RANGE))
}

/** Clamp the view's offset so the scaled image always covers the
 *  viewport (no blank edge can ever show); an axis whose scaled size IS
 *  the viewport pins at 0. Returns a NEW view (the dialog's state stays
 *  immutable-ish). */
export function clampOffset(view: CropView): CropView {
  const clampAxis = (offset: number, scaled: number, viewport: number): number => {
    if (scaled <= viewport) return (viewport - scaled) / 2 // centered
    return Math.min(0, Math.max(viewport - scaled, offset))
  }
  return {
    ...view,
    offsetX: clampAxis(view.offsetX, view.imageWidth * view.scale, view.viewport),
    offsetY: clampAxis(view.offsetY, view.imageHeight * view.scale, view.viewport),
  }
}

/** The opening view: cover-fit, the image centered in the window. */
export function initialView(imageWidth: number, imageHeight: number, viewport: number): CropView {
  const scale = fitScale(imageWidth, imageHeight, viewport)
  return {
    viewport,
    imageWidth,
    imageHeight,
    scale,
    offsetX: (viewport - imageWidth * scale) / 2,
    offsetY: (viewport - imageHeight * scale) / 2,
  }
}

/** The square source rectangle (image-pixel coordinates) the viewport
 *  window covers — what the crop reads out of the image. */
export function cropSourceRect(view: CropView): { sx: number; sy: number; side: number } {
  const sx = -view.offsetX / view.scale
  const sy = -view.offsetY / view.scale
  // -0 normalizes to +0: the rect is a data value, never a signed zero.
  return {
    sx: sx === 0 ? 0 : sx,
    sy: sy === 0 ? 0 : sy,
    side: view.viewport / view.scale,
  }
}

/** Drag the image by a viewport-space delta (the image follows the
 *  pointer), the edges clamped. */
export function panBy(view: CropView, dx: number, dy: number): CropView {
  return clampOffset({ ...view, offsetX: view.offsetX + dx, offsetY: view.offsetY + dy })
}

/** Re-scale with the window's CENTER fixed on the same image point (the
 *  wheel/slider zoom never jumps the framing). */
export function withScale(view: CropView, scale: number): CropView {
  const before = cropSourceRect(view)
  const cx = before.sx + before.side / 2
  const cy = before.sy + before.side / 2
  const side = view.viewport / scale
  return clampOffset({
    ...view,
    scale,
    offsetX: -(cx - side / 2) * scale,
    offsetY: -(cy - side / 2) * scale,
  })
}
