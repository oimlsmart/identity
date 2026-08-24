<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// AvatarCropDialog — the crop step of the account console's "Change the
// picture" (the wave-536 UX): pick a raster file, frame the SQUARE crop
// here (drag to position, the slider or the wheel to zoom, the round
// preview showing the avatar as it will render), confirm, and the crop
// is produced CLIENT-SIDE (canvas → a 256 px PNG blob — lib/avatar-crop
// carries the geometry). The upload route's cap + type allowlist are
// unchanged and re-judged server-side; the route is never trusted to
// fix the image.
//
// The size note names the server's cap honestly (the parent passes it).
// The dialog never uploads: it emits the finished blob; the parent owns
// the wire.
// ═══════════════════════════════════════════════════════════════════
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { t } from '../i18n'
import {
  AVATAR_OUTPUT_SIZE,
  AVATAR_OUTPUT_TYPE,
  cropSourceRect,
  fitScale,
  initialView,
  panBy,
  withScale,
  zoomAt,
  zoomPosition,
  type CropView,
} from '../lib/avatar-crop'

const props = defineProps<{
  /** The picked raster file (the parent's type/size checks already ran). */
  file: File
  /** The server's upload cap, named in the honest size note. */
  maxBytes: number
  /** The parent's upload in flight: the confirm button's busy posture. */
  busy?: boolean
}>()

const emit = defineEmits<{
  confirm: [blob: Blob]
  cancel: []
}>()

/** The square viewport's side, CSS px. */
const VIEWPORT = 280

const canvasRef = ref<HTMLCanvasElement | null>(null)
const previewRef = ref<HTMLCanvasElement | null>(null)
const view = ref<CropView | null>(null)
/** The slider's position in [0, 1] (geometric over the zoom range). */
const zoomT = ref(0)
const decodeError = ref(false)

const maxMb = Math.round((props.maxBytes / 1024 / 1024) * 10) / 10

let image: HTMLImageElement | null = null
let objectUrl = ''
let dragging = false
let lastX = 0
let lastY = 0

/** The canvas backing store follows the device pixel ratio (crisp on
 *  retina); the canvas shows exactly the crop (WYSIWYG). */
function draw(): void {
  const canvas = canvasRef.value
  const v = view.value
  if (!canvas || !v || !image) return
  const dpr = window.devicePixelRatio || 1
  canvas.width = VIEWPORT * dpr
  canvas.height = VIEWPORT * dpr
  const ctx = canvas.getContext('2d')
  if (!ctx) return
  ctx.imageSmoothingEnabled = true
  ctx.imageSmoothingQuality = 'high'
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.clearRect(0, 0, VIEWPORT, VIEWPORT)
  ctx.drawImage(
    image,
    0, 0, image.naturalWidth, image.naturalHeight,
    v.offsetX, v.offsetY, v.imageWidth * v.scale, v.imageHeight * v.scale,
  )
  // The round preview: the avatar as it will render, copied from the
  // crop canvas (never a second decode).
  const preview = previewRef.value
  const pctx = preview?.getContext('2d')
  if (preview && pctx) {
    pctx.clearRect(0, 0, preview.width, preview.height)
    pctx.drawImage(canvas, 0, 0, preview.width, preview.height)
  }
}

function setView(next: CropView): void {
  view.value = next
  zoomT.value = zoomPosition(fitScale(next.imageWidth, next.imageHeight, next.viewport), next.scale)
  draw()
}

function onPointerDown(e: PointerEvent): void {
  if (!view.value) return
  dragging = true
  lastX = e.clientX
  lastY = e.clientY
  ;(e.currentTarget as HTMLElement).setPointerCapture(e.pointerId)
}

function onPointerMove(e: PointerEvent): void {
  if (!dragging || !view.value) return
  const v = view.value
  setView(panBy(v, e.clientX - lastX, e.clientY - lastY))
  lastX = e.clientX
  lastY = e.clientY
}

function onPointerUp(): void {
  dragging = false
}

function onWheel(e: WheelEvent): void {
  const v = view.value
  if (!v) return
  e.preventDefault()
  const fit = fitScale(v.imageWidth, v.imageHeight, v.viewport)
  const next = zoomAt(fit, Math.min(1, Math.max(0, zoomPosition(fit, v.scale) - e.deltaY * 0.002)))
  setView(withScale(v, next))
}

function onZoomInput(e: Event): void {
  const v = view.value
  if (!v) return
  const t01 = Number((e.target as HTMLInputElement).value) / 100
  setView(withScale(v, zoomAt(fitScale(v.imageWidth, v.imageHeight, v.viewport), t01)))
}

function onKey(e: KeyboardEvent): void {
  if (e.key === 'Escape') emit('cancel')
}

/** The crop, rendered: the square source rect → a AVATAR_OUTPUT_SIZE px
 *  PNG blob. The parent owns the cap check + the upload. */
function confirmCrop(): void {
  const v = view.value
  if (!v || !image || props.busy) return
  const rect = cropSourceRect(v)
  const out = document.createElement('canvas')
  out.width = AVATAR_OUTPUT_SIZE
  out.height = AVATAR_OUTPUT_SIZE
  const ctx = out.getContext('2d')
  if (!ctx) return
  ctx.imageSmoothingEnabled = true
  ctx.imageSmoothingQuality = 'high'
  ctx.drawImage(image, rect.sx, rect.sy, rect.side, rect.side, 0, 0, AVATAR_OUTPUT_SIZE, AVATAR_OUTPUT_SIZE)
  out.toBlob((blob) => {
    if (blob) emit('confirm', blob)
  }, AVATAR_OUTPUT_TYPE)
}

onMounted(() => {
  objectUrl = URL.createObjectURL(props.file)
  const img = new Image()
  img.onload = () => {
    image = img
    setView(initialView(img.naturalWidth, img.naturalHeight, VIEWPORT))
  }
  img.onerror = () => { decodeError.value = true }
  img.src = objectUrl
  window.addEventListener('keydown', onKey)
})

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey)
  if (objectUrl) URL.revokeObjectURL(objectUrl)
})
</script>

<template>
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/30 dark:bg-black/50 px-4"
    role="dialog"
    aria-modal="true"
    :aria-label="t('account.profile.cropTitle')"
    data-testid="account-avatar-crop"
    @click.self="emit('cancel')"
  >
    <div class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-xl p-6 w-full max-w-sm">
      <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-4">{{ t('account.profile.cropTitle') }}</h2>

      <template v-if="decodeError">
        <p class="text-sm text-red-600 dark:text-red-400" data-testid="account-avatar-crop-error">{{ t('account.profile.cropDecodeError') }}</p>
        <div class="mt-4 flex justify-end">
          <button
            type="button"
            class="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            data-testid="account-avatar-crop-cancel"
            @click="emit('cancel')"
          >{{ t('account.profile.cancel') }}</button>
        </div>
      </template>

      <template v-else>
        <div class="flex items-start gap-4">
          <!-- The crop window: what shows IS what uploads. -->
          <canvas
            ref="canvasRef"
            :width="VIEWPORT"
            :height="VIEWPORT"
            :style="{ width: `${VIEWPORT}px`, height: `${VIEWPORT}px` }"
            class="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-900 cursor-grab active:cursor-grabbing touch-none select-none shrink-0"
            data-testid="account-avatar-crop-canvas"
            @pointerdown="onPointerDown"
            @pointermove="onPointerMove"
            @pointerup="onPointerUp"
            @pointercancel="onPointerUp"
            @wheel="onWheel"
          />
          <!-- The live preview: the avatar as it will render. -->
          <div class="pt-1">
            <canvas
              ref="previewRef"
              width="48"
              height="48"
              class="w-12 h-12 rounded-full border border-slate-200 dark:border-slate-700"
              data-testid="account-avatar-crop-preview"
            />
            <p class="mt-1 text-[10px] text-slate-400 dark:text-slate-500 text-center">{{ t('account.profile.cropPreview') }}</p>
          </div>
        </div>

        <label class="mt-4 flex items-center gap-3 text-xs font-medium text-slate-700 dark:text-slate-300">
          {{ t('account.profile.cropZoom') }}
          <input
            type="range"
            min="0"
            max="100"
            :value="Math.round(zoomT * 100)"
            class="flex-1 accent-brand-600"
            data-testid="account-avatar-crop-zoom"
            @input="onZoomInput"
          />
        </label>

        <!-- The honest size note: the crop is the final picture; the
             server's cap is named, never hidden. -->
        <p class="mt-3 text-xs text-slate-500 dark:text-slate-400" data-testid="account-avatar-crop-note">
          {{ t('account.profile.cropNote', { size: AVATAR_OUTPUT_SIZE, max: maxMb }) }}
        </p>

        <div class="mt-5 flex justify-end gap-2">
          <button
            type="button"
            :disabled="busy"
            class="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
            data-testid="account-avatar-crop-cancel"
            @click="emit('cancel')"
          >{{ t('account.profile.cancel') }}</button>
          <button
            type="button"
            :disabled="!view || busy"
            class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
            data-testid="account-avatar-crop-confirm"
            @click="confirmCrop"
          >{{ busy ? t('account.profile.avatarBusy') : t('account.profile.cropConfirm') }}</button>
        </div>
      </template>
    </div>
  </div>
</template>
