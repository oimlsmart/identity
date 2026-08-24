// ═══════════════════════════════════════════════════════════════════
// The local QR renderer (TODO.identity-sso/03) — the TOTP enrollment's
// otpauth:// URI rendered client-side, so the secret NEVER leaves the
// page (never an external image service). Hand-rolled and dependency-
// free, the house doctrine applied to the client half: byte mode, error
// correction level M, versions 1–10 (an otpauth URI is 60–120 chars —
// version 6's 106-byte capacity covers the ordinary ones, 10 the
// generous bound).
//
// The implementation follows ISO/IEC 18004's structure: the byte-mode
// bitstream, the Reed-Solomon blocks (the per-version structure table
// below), the fixed function patterns (finders, timing, alignment), the
// eight mask candidates scored by the standard's penalty rules, and the
// format information's BCH(15,5) with the 0x5412 mask.
//
// The proof: src/__tests__/id-qr.test.ts pins the matrices against
// reference outputs (generated with the segno library at development
// time — a dev-time cross-check, never a shipped dependency).
// ═══════════════════════════════════════════════════════════════════

export class QrError extends Error {}

// ── the Galois field GF(2⁸) (the 0x11D primitive polynomial) ─────────

const GF_EXP = new Uint8Array(512)
const GF_LOG = new Uint8Array(256)
;(() => {
  let x = 1
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x
    GF_LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11d
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]!
})()

function gfMul(a: number, b: number): number {
  return a === 0 || b === 0 ? 0 : GF_EXP[GF_LOG[a]! + GF_LOG[b]!]!
}

/** The Reed-Solomon generator polynomial of the given degree. */
function rsGenerator(degree: number): Uint8Array {
  let poly = new Uint8Array([1])
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1)
    for (let j = 0; j < poly.length; j++) {
      next[j] = next[j]! ^ gfMul(poly[j]!, GF_EXP[i]!)
      next[j + 1] = next[j + 1]! ^ poly[j]!
    }
    poly = next
  }
  return poly
}

/** The ECC bytes for a data block (the polynomial long division). The
 *  generator's coefficients are stored ASCENDING ([g0 … g_{d-1}, 1]); the
 *  shift-register step consumes them BELOW the leading term, descending. */
function rsRemainder(data: Uint8Array, degree: number): Uint8Array {
  const generator = rsGenerator(degree)
  const out = new Uint8Array(degree)
  for (let i = 0; i < data.length; i++) {
    const factor = data[i]! ^ out[0]!
    out.copyWithin(0, 1)
    out[degree - 1] = 0
    for (let j = 0; j < degree; j++) out[j] = out[j]! ^ gfMul(generator[degree - 1 - j]!, factor)
  }
  return out
}

// ── the per-version parameters (level M, ISO/IEC 18004) ──────────────
// [total codewords, data codewords, ec per block, block structure as
// [count, data codewords per block] groups, alignment pattern centers]
const VERSIONS: Array<null | { total: number; data: number; ecPerBlock: number; blocks: Array<[number, number]>; align: number[] }> = [
  null,
  { total: 26, data: 16, ecPerBlock: 10, blocks: [[1, 16]], align: [] },
  { total: 44, data: 28, ecPerBlock: 16, blocks: [[1, 28]], align: [6, 18] },
  { total: 70, data: 44, ecPerBlock: 26, blocks: [[1, 44]], align: [6, 22] },
  { total: 100, data: 64, ecPerBlock: 18, blocks: [[2, 32]], align: [6, 26] },
  { total: 134, data: 86, ecPerBlock: 24, blocks: [[2, 43]], align: [6, 30] },
  { total: 172, data: 108, ecPerBlock: 16, blocks: [[4, 27]], align: [6, 34] },
  { total: 196, data: 124, ecPerBlock: 18, blocks: [[4, 31]], align: [6, 22, 38] },
  { total: 242, data: 154, ecPerBlock: 22, blocks: [[2, 38], [2, 39]], align: [6, 24, 42] },
  { total: 292, data: 182, ecPerBlock: 22, blocks: [[3, 36], [2, 37]], align: [6, 26, 46] },
  { total: 346, data: 216, ecPerBlock: 26, blocks: [[4, 43], [1, 44]], align: [6, 28, 50] },
]

// ── the bitstream ────────────────────────────────────────────────────

class BitStream {
  bits: number[] = []
  push(value: number, length: number): void {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1)
  }
  get length(): number { return this.bits.length }
}

// ── the format information (BCH(15,5) over the level+mask, XOR 0x5412) ──

function formatBits(mask: number): number {
  // Level M is the two zero bits.
  const data = (0b00 << 3) | mask
  let rem = data << 10
  const generator = 0x537 // x^10 + x^8 + x^5 + x^4 + x^2 + x + 1
  for (let i = 14; i >= 10; i--) {
    if ((rem >>> i) & 1) rem ^= generator << (i - 10)
  }
  return (((data << 10) | rem) ^ 0x5412) & 0x7fff
}

// ── the mask patterns ────────────────────────────────────────────────

function maskBit(mask: number, r: number, c: number): boolean {
  switch (mask) {
    case 0: return (r + c) % 2 === 0
    case 1: return r % 2 === 0
    case 2: return c % 3 === 0
    case 3: return (r + c) % 3 === 0
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0
    case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0
    case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0
    default: throw new QrError(`mask ${mask} does not exist`)
  }
}

// ── the matrix assembly ──────────────────────────────────────────────

function buildMatrix(data: Uint8Array, version: number): Uint8Array {
  const params = VERSIONS[version]!
  const size = version * 4 + 17

  // The bitstream: byte mode (0100), the count (8 bits v1–9, 16 from
  // v10), the bytes, the terminator, the pad.
  const stream = new BitStream()
  stream.push(0b0100, 4)
  stream.push(data.length, version <= 9 ? 8 : 16)
  for (const byte of data) stream.push(byte, 8)
  const capacityBits = params.data * 8
  stream.push(0, Math.min(4, capacityBits - stream.length))
  while (stream.length % 8 !== 0) stream.push(0, 1)
  const dataCodewords: number[] = []
  for (let i = 0; i < stream.length; i += 8) {
    let byte = 0
    for (let j = 0; j < 8; j++) byte = (byte << 1) | stream.bits[i + j]!
    dataCodewords.push(byte)
  }
  for (let pad = 0; dataCodewords.length < params.data; pad++) {
    dataCodewords.push(pad % 2 === 0 ? 0xec : 0x11)
  }

  // The blocks + the ECC, then the interleaved codeword stream.
  const dataBlocks: Uint8Array[] = []
  const eccBlocks: Uint8Array[] = []
  let at = 0
  for (const [count, blockSize] of params.blocks) {
    for (let i = 0; i < count; i++) {
      const block = new Uint8Array(dataCodewords.slice(at, at + blockSize))
      dataBlocks.push(block)
      eccBlocks.push(rsRemainder(block, params.ecPerBlock))
      at += blockSize
    }
  }
  const interleaved: number[] = []
  const maxData = Math.max(...dataBlocks.map(b => b.length))
  for (let i = 0; i < maxData; i++) {
    for (const block of dataBlocks) if (i < block.length) interleaved.push(block[i]!)
  }
  for (let i = 0; i < params.ecPerBlock; i++) {
    for (const block of eccBlocks) interleaved.push(block[i]!)
  }
  if (interleaved.length !== params.total) {
    throw new QrError(`the interleaved stream is ${interleaved.length} codewords, the version's total is ${params.total} — the structure table is wrong`)
  }

  // The function patterns. `modules` holds the final bits; `reserved`
  // marks the function cells the data placement must skip.
  const modules = new Uint8Array(size * size)
  const reserved = new Uint8Array(size * size)
  const set = (r: number, c: number, dark: boolean, reserve = true): void => {
    modules[r * size + c] = dark ? 1 : 0
    if (reserve) reserved[r * size + c] = 1
  }

  // The finders + separators.
  const finder = (r0: number, c0: number): void => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = r0 + dr
        const c = c0 + dc
        if (r < 0 || c < 0 || r >= size || c >= size) continue
        const inPattern = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6
        const dark = inPattern && (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4))
        set(r, c, dark)
      }
    }
  }
  finder(0, 0)
  finder(0, size - 7)
  finder(size - 7, 0)

  // The timing patterns.
  for (let i = 8; i < size - 8; i++) {
    set(6, i, i % 2 === 0)
    set(i, 6, i % 2 === 0)
  }

  // The alignment patterns. The skip rule is the standard's corner rule:
  // only the three patterns whose centers fall on the FINDER corners are
  // omitted; patterns crossing the timing row/column (centers at
  // (6, y) / (x, 6) in versions ≥ 7) ARE drawn and overwrite the timing
  // cells.
  const align = params.align
  for (let ai = 0; ai < align.length; ai++) {
    for (let bi = 0; bi < align.length; bi++) {
      const isFinderCorner =
        (ai === 0 && bi === 0) ||
        (ai === 0 && bi === align.length - 1) ||
        (ai === align.length - 1 && bi === 0)
      if (isFinderCorner) continue
      const r = align[ai]!
      const c = align[bi]!
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1
          set(r + dr, c + dc, dark)
        }
      }
    }
  }

  // The format information's placeholders (the real bits land with the
  // chosen mask, after the data placement).
  const formatCells: Array<[number, number]> = []
  for (let i = 0; i <= 8; i++) {
    if (i === 6) continue
    formatCells.push([8, i]) // the top-left horizontal arm
  }
  for (let i = 0; i <= 7; i++) {
    if (i === 6) continue
    formatCells.push([i, 8]) // the top-left vertical arm
  }
  for (const [r, c] of formatCells) reserved[r * size + c] = 1
  // The second copies: the bottom-left vertical + the top-right horizontal.
  for (let i = 0; i <= 7; i++) reserved[(size - 1 - i) * size + 8] = 1
  for (let i = 0; i <= 7; i++) reserved[8 * size + (size - 8 + i)] = 1
  // The dark module.
  set(size - 8, 8, true)

  // The version information's reservation (versions ≥ 7): two 6×3/3×6
  // blocks beside the top-right and bottom-left finders. The bits land
  // after the mask choice (writeVersionBits).
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3)
      const b = Math.floor(i / 3)
      reserved[b * size + a] = 1
      reserved[a * size + b] = 1
    }
  }

  // The data placement: the right-to-left column pairs, the zigzag,
  // skipping the timing column and every reserved cell.
  let bitIndex = 0
  const totalBits = interleaved.length * 8
  const bitAt = (i: number): number => (i < totalBits ? (interleaved[i >>> 3]! >>> (7 - (i & 7))) & 1 : 0)
  let upward = true
  for (let c0 = size - 1; c0 > 0; c0 -= 2) {
    if (c0 === 6) c0 = 5 // the timing column
    for (let step = 0; step < size; step++) {
      const r = upward ? size - 1 - step : step
      for (const c of [c0, c0 - 1]) {
        if (reserved[r * size + c]) continue
        if (bitAt(bitIndex) === 1) modules[r * size + c] = 1
        bitIndex++
      }
    }
    upward = !upward
  }

  return modules
}

/** The mask's penalty score (the four standard rules, ISO/IEC 18004
 *  §7.8.3.1 — the scoring here matches the reference implementation the
 *  tests pin against, rule for rule). */
function penalty(modules: Uint8Array, size: number): number {
  let score = 0
  const at = (r: number, c: number) => modules[r * size + c]!

  // Rule 1: runs of five+ same-color modules in a row/column
  // (N1 = 3, +1 per module beyond five).
  for (let r = 0; r < size; r++) {
    let sameRow = 0
    let sameCol = 0
    let lastRow: number | null = null
    let lastCol: number | null = null
    for (let c = 0; c < size; c++) {
      const rowModule = at(r, c)
      if (rowModule === lastCol) {
        sameCol++
      } else {
        if (sameCol >= 5) score += 3 + (sameCol - 5)
        lastCol = rowModule
        sameCol = 1
      }
      const colModule = at(c, r)
      if (colModule === lastRow) {
        sameRow++
      } else {
        if (sameRow >= 5) score += 3 + (sameRow - 5)
        lastRow = colModule
        sameRow = 1
      }
    }
    if (sameCol >= 5) score += 3 + (sameCol - 5)
    if (sameRow >= 5) score += 3 + (sameRow - 5)
  }

  // Rule 2: the 2×2 same-color blocks (N2 = 3 each).
  for (let r = 0; r + 1 < size; r++) {
    for (let c = 0; c + 1 < size; c++) {
      const sum = at(r, c) + at(r, c + 1) + at(r + 1, c) + at(r + 1, c + 1)
      if (sum === 4 || sum === 0) score += 3
    }
  }

  // Rule 3: the finder-like 1:1:3:1:1 patterns with a four-module light
  // flank, either side (N3 = 40 each) — scanned as an 11-bit window:
  // 10111010000 (flank after) or 00001011101 (flank before).
  for (let r = 0; r < size; r++) {
    let bitsCol = 0
    let bitsRow = 0
    for (let c = 0; c < size; c++) {
      bitsCol = ((bitsCol << 1) & 0x7ff) | at(r, c)
      if (c >= 10 && (bitsCol === 0x5d0 || bitsCol === 0x05d)) score += 40
      bitsRow = ((bitsRow << 1) & 0x7ff) | at(c, r)
      if (c >= 10 && (bitsRow === 0x5d0 || bitsRow === 0x05d)) score += 40
    }
  }

  // Rule 4: the dark-module ratio's distance from 50%, in 5% steps
  // (N4 = 10 per step, the reference's ceiling step).
  let dark = 0
  for (const bit of modules) dark += bit
  score += Math.abs(Math.ceil((dark * 100) / (size * size) / 5) - 10) * 10

  return score
}

/** Render the format information for the chosen mask onto the matrix.
 *  The mapping is the standard's fixed one (ISO/IEC 18004 §7.9.1):
 *  the first copy carries bit 14 at (8, 0) along the row to (8, 5),
 *  then (8, 7), (8, 8), then up the column from (7, 8) to (0, 8) with
 *  bit 0; the second copy carries bit 14 at (size-1, 8) upward to
 *  (size-7, 8) with bit 8, then (8, size-8) to (8, size-1) with bits
 *  7 down to 0. */
function writeFormatBits(modules: Uint8Array, size: number, mask: number): void {
  const bits = formatBits(mask)
  const bit = (i: number) => (bits >>> i) & 1
  // The first copy.
  modules[8 * size + 0] = bit(14)
  modules[8 * size + 1] = bit(13)
  modules[8 * size + 2] = bit(12)
  modules[8 * size + 3] = bit(11)
  modules[8 * size + 4] = bit(10)
  modules[8 * size + 5] = bit(9)
  modules[8 * size + 7] = bit(8)
  modules[8 * size + 8] = bit(7)
  modules[7 * size + 8] = bit(6)
  modules[5 * size + 8] = bit(5)
  modules[4 * size + 8] = bit(4)
  modules[3 * size + 8] = bit(3)
  modules[2 * size + 8] = bit(2)
  modules[1 * size + 8] = bit(1)
  modules[0 * size + 8] = bit(0)
  // The second copy.
  for (let i = 0; i < 7; i++) modules[(size - 1 - i) * size + 8] = bit(14 - i)
  for (let i = 0; i < 8; i++) modules[8 * size + (size - 8 + i)] = bit(7 - i)
  // The dark module (always set; already placed).
  modules[(size - 8) * size + 8] = 1
}

/** The smallest version whose level-M data capacity holds the payload:
 *  the mode indicator (4 bits) + the character count (8 bits through
 *  version 9, 16 from version 10) + the content bytes must fit (the
 *  terminator shrinks to nothing when the stream lands exactly on the
 *  capacity). */
function versionFor(dataLength: number): number {
  const version = VERSIONS.findIndex((v, i) => {
    if (v === null) return false
    const cciBits = i <= 9 ? 8 : 16
    return 4 + cciBits + dataLength * 8 <= v.data * 8
  })
  if (version < 0) throw new QrError(`the payload (${dataLength} bytes) exceeds the renderer's level-M bound (208 bytes)`)
  return version
}

/** The version information's 18 bits (BCH(18,6), generator
 *  x¹²+x¹¹+x¹⁰+x⁹+x⁸+x⁵+x²+1 — the version number followed by its
 *  12 check bits). */
function versionBits(version: number): number {
  let rem = version << 12
  const generator = 0x1f25
  for (let i = 17; i >= 12; i--) {
    if ((rem >>> i) & 1) rem ^= generator << (i - 12)
  }
  return ((version << 12) | rem) & 0x3ffff
}

/** Draw the version information (versions ≥ 7): bit i (LSB first) at
 *  (floor(i/3), size-11 + i%3) beside the top-right finder, and the
 *  transpose beside the bottom-left one. */
function writeVersionBits(modules: Uint8Array, size: number, version: number): void {
  if (version < 7) return
  const bits = versionBits(version)
  for (let i = 0; i < 18; i++) {
    const bit = (bits >>> i) & 1
    const a = size - 11 + (i % 3)
    const b = Math.floor(i / 3)
    modules[b * size + a] = bit
    modules[a * size + b] = bit
  }
}

/** The matrix under ONE mask (the tests' seam: the reference pinning
 *  checks every mask's output against the golden, so a mask-pattern or
 *  format-bit bug can never hide behind the penalty choice). */
export function qrMatrixForMask(text: string, mask: number): { size: number; modules: Uint8Array } {
  const data = new TextEncoder().encode(text)
  const version = versionFor(data.length)
  const size = version * 4 + 17
  const base = buildMatrix(data, version)
  const reserved = reservedCells(size, version)
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!reserved[r * size + c] && maskBit(mask, r, c)) base[r * size + c] ^= 1
    }
  }
  writeFormatBits(base, size, mask)
  writeVersionBits(base, size, version)
  return { size, modules: base }
}

/** The QR matrix for a text payload (byte mode, level M, the smallest
 *  fitting version ≤ 10, the best mask by the penalty rules). Answers
 *  the size×size module grid (1 = dark). Throws QrError when the payload
 *  exceeds version 10's level-M byte-mode capacity (208 bytes). */
export function qrMatrix(text: string): { size: number; modules: Uint8Array } {
  const data = new TextEncoder().encode(text)
  const version = versionFor(data.length)
  const size = version * 4 + 17

  let best: { modules: Uint8Array; score: number } | null = null
  for (let mask = 0; mask < 8; mask++) {
    const candidate = qrMatrixForMask(text, mask)
    const score = penalty(candidate.modules, size)
    if (!best || score < best.score) best = { modules: candidate.modules, score }
  }
  return { size, modules: best!.modules }
}

/** The reserved (function-pattern) cells for a version — the same
 *  placement buildMatrix uses, factored so the mask pass can re-derive
 *  it without touching the data. */
function reservedCells(size: number, version: number): Uint8Array {
  const reserved = new Uint8Array(size * size)
  const mark = (r: number, c: number): void => { reserved[r * size + c] = 1 }
  const finder = (r0: number, c0: number): void => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = r0 + dr
        const c = c0 + dc
        if (r >= 0 && c >= 0 && r < size && c < size) mark(r, c)
      }
    }
  }
  finder(0, 0)
  finder(0, size - 7)
  finder(size - 7, 0)
  for (let i = 8; i < size - 8; i++) { mark(6, i); mark(i, 6) }
  const align = VERSIONS[version]!.align
  for (let ai = 0; ai < align.length; ai++) {
    for (let bi = 0; bi < align.length; bi++) {
      const isFinderCorner =
        (ai === 0 && bi === 0) ||
        (ai === 0 && bi === align.length - 1) ||
        (ai === align.length - 1 && bi === 0)
      if (isFinderCorner) continue
      const r = align[ai]!
      const c = align[bi]!
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) mark(r + dr, c + dc)
    }
  }
  for (let i = 0; i <= 8; i++) { if (i !== 6) mark(8, i) }
  for (let i = 0; i <= 7; i++) { if (i !== 6) mark(i, 8) }
  for (let i = 0; i <= 7; i++) mark(size - 1 - i, 8)
  for (let i = 0; i <= 7; i++) mark(8, size - 8 + i)
  // The version information's cells (versions ≥ 7).
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3)
      const b = Math.floor(i / 3)
      mark(b, a)
      mark(a, b)
    }
  }
  return reserved
}

/** The matrix as an SVG string (crisp at any size, no canvas
 *  dependency). `border` is the quiet zone in modules (4 per the
 *  standard). */
export function qrSvg(text: string, opts?: { moduleSize?: number; border?: number; dark?: string; light?: string }): string {
  const { size, modules } = qrMatrix(text)
  const border = opts?.border ?? 4
  const moduleSize = opts?.moduleSize ?? 4
  const dark = opts?.dark ?? '#0f172a'
  const light = opts?.light ?? '#ffffff'
  const total = (size + border * 2) * moduleSize
  const rects: string[] = []
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules[r * size + c] === 1) {
        rects.push(`<rect x="${(c + border) * moduleSize}" y="${(r + border) * moduleSize}" width="${moduleSize}" height="${moduleSize}"/>`)
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges" role="img"><rect width="${total}" height="${total}" fill="${light}"/><g fill="${dark}">${rects.join('')}</g></svg>`
}
