// ─────────────────────────────────────────────────────────────────────
// The local QR renderer's proof (TODO.identity-sso/03): src/qr.ts is
// hand-rolled (byte mode, level M, versions 1–10) and pinned here
// against the reference matrices (qr-golden.ts — rendered with the
// qrcode package at development time, every mask + the auto selection).
// A drift in the bitstream, the Reed-Solomon blocks, the placement, the
// masks, the format/version information, or the penalty choice fails a
// leg exactly.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import { qrMatrix, qrMatrixForMask, qrSvg, QrError } from '../qr'
import { QR_GOLDEN } from './qr-golden'

function unpack(packed: string, size: number): Uint8Array {
  const bin = atob(packed.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const bits = new Uint8Array(size * size)
  for (let i = 0; i < size * size; i++) bits[i] = (bytes[i >>> 3]! >>> (7 - (i & 7))) & 1
  return bits
}

describe('the local QR renderer (src/qr.ts)', () => {
  it('matches the reference matrices, every mask + the penalty-driven auto choice', () => {
    for (const entry of QR_GOLDEN) {
      for (let mask = 0; mask < 8; mask++) {
        const golden = entry.masks[String(mask)]!
        const mine = qrMatrixForMask(entry.payload, mask)
        expect(mine.size, `size drift (mask ${mask})`).toBe(golden.size)
        expect(
          mine.modules.every((b, i) => b === unpack(golden.packed, golden.size)[i]),
          `matrix drift on mask ${mask} for ${entry.payload.slice(0, 40)}…`,
        ).toBe(true)
      }
      const auto = qrMatrix(entry.payload)
      expect(auto.size).toBe(entry.auto.size)
      expect(
        auto.modules.every((b, i) => b === unpack(entry.auto.packed, entry.auto.size)[i]),
        `the auto mask selection drifted for ${entry.payload.slice(0, 40)}…`,
      ).toBe(true)
    }
  })

  it('renders an otpauth URI as a version-appropriate matrix with the quiet zone in the SVG', () => {
    const uri = 'otpauth://totp/OIML%20SMART%20Identity:casey@example.org?secret=JBSWY3DPEHPK3PXP&issuer=OIML%20SMART%20Identity&algorithm=SHA1&digits=6&period=30'
    const { size, modules } = qrMatrix(uri)
    expect(size).toBe(49) // version 8: the 134-byte payload at level M
    expect(modules.length).toBe(size * size)
    // The finder corners are dark — the matrix is real, not vacuous.
    expect(modules[0]).toBe(1)
    const svg = qrSvg(uri)
    expect(svg).toContain('<svg')
    expect(svg).toContain('shape-rendering="crispEdges"')
    expect(svg).not.toContain('script')
  })

  it('refuses a payload past the level-M bound honestly', () => {
    expect(() => qrMatrix('x'.repeat(300))).toThrow(QrError)
  })
})
