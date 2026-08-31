// The typography audit (the visual-elevation wave, move 1): measure the
// sign-in page's computed type scale honestly, light AND dark, plus the
// contrast ratios of the muted text against the actual backgrounds.
import puppeteer from 'puppeteer'

const BASE = process.argv[2] ?? 'http://localhost:5690'

function luminance([r, g, b]) {
  const f = (c) => {
    c /= 255
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
  }
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
}
function parseRgb(s) {
  const m = s.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/)
  if (m) return [Number(m[1]), Number(m[2]), Number(m[3])]
  if (s.startsWith('#')) {
    const n = parseInt(s.slice(1), 16)
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
  }
  const ok = s.match(/okl(?:ch|ab)\(\s*([\d.]+)%?\s+([\d.-]+)\s+([\d.-]+)/)
  if (ok) {
    // oklch(L, C, H) or oklab(L, a, b): heuristic — 3rd component > 2π is a hue
    const L = Number(ok[1])
    const c2 = Number(ok[2]); const c3 = Number(ok[3])
    let a, b
    if (s.startsWith('oklab')) { a = c2; b = c3 } else { a = c2 * Math.cos(c3 * Math.PI / 180); b = c2 * Math.sin(c3 * Math.PI / 180) }
    const l_ = L + 0.3963377774 * a + 0.2158037573 * b
    const m_ = L - 0.1055613458 * a - 0.0638541728 * b
    const s_ = L - 0.0894841775 * a - 1.2914855480 * b
    const l = l_ ** 3, m2 = m_ ** 3, s3 = s_ ** 3
    const toSrgb = (x) => {
      const v = 255 * (x <= 0.0031308 ? 12.92 * x : 1.055 * Math.pow(x, 1 / 2.4) - 0.055)
      return Math.max(0, Math.min(255, Math.round(v)))
    }
    return [
      toSrgb(4.0767416621 * l - 3.3077115913 * m2 + 0.2309699292 * s3),
      toSrgb(-1.2684380046 * l + 2.6097574011 * m2 - 0.3413193965 * s3),
      toSrgb(-0.0041960863 * l - 0.7034186147 * m2 + 1.7076147010 * s3),
    ]
  }
  return null
}

const SELECTORS = [
  ['h1 (heading)', 'h1'],
  ['email label', '[data-testid="login-email"]', 'label'],
  ['email input', '[data-testid="login-email"]'],
  ['password input', '[data-testid="login-password"]'],
  ['submit button', '[data-testid="login-submit"]'],
  ['passkey button', '[data-testid="login-passkey"]'],
  ['or divider', null], // resolved in-page: the uppercase span
  ['forgot link', '[data-testid="login-forgot"]'],
  ['join line', '[data-testid="login-join"]'],
  ['legitimacy line', '[data-testid="login-legitimacy"]'],
  ['footer', '[data-testid="shell-footer"]'],
]

async function measure(page, scheme) {
  await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: scheme }])
  await page.evaluate((s) => {
    localStorage.setItem('oiml-theme', s)
    document.documentElement.classList.toggle('dark', s === 'dark')
  }, scheme)
  const rows = []
  for (const [name, sel, kind] of SELECTORS) {
    const row = await page.evaluate(([name, sel, kind]) => {
      let el = sel ? document.querySelector(sel) : null
      if (kind === 'label') el = document.querySelector('form label')
      if (name === 'or divider') el = [...document.querySelectorAll('span')].find((s) => s.className.includes('uppercase'))
      if (!el) return { name, missing: true }
      const cs = getComputedStyle(el)
      // canvas normalizes any CSS color (oklch included) to rgb()
      const ctx = document.createElement('canvas').getContext('2d')
      const norm = (c) => { ctx.fillStyle = c; return ctx.fillStyle }
      // walk up for the effective background
      let bg = null
      for (let n = el; n; n = n.parentElement) {
        const b = getComputedStyle(n).backgroundColor
        if (b && !b.startsWith('rgba(0, 0, 0, 0')) { bg = norm(b); break }
      }
      return { name, fontSize: cs.fontSize, fontWeight: cs.fontWeight, color: norm(cs.color), bg }
    }, [name, sel, kind])
    if (row.missing) { rows.push({ name, missing: true }); continue }
    const fg = parseRgb(row.color); const bg = row.bg ? parseRgb(row.bg) : null
    let ratio = null
    if (fg && bg) {
      const l1 = luminance(fg); const l2 = luminance(bg)
      const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1]
      ratio = ((hi + 0.05) / (lo + 0.05)).toFixed(2)
    }
    rows.push({ ...row, contrast: ratio })
  }
  return rows
}

const browser = await puppeteer.launch({ headless: 'shell', args: ['--no-sandbox'] })
const page = await browser.newPage()
await page.setViewport({ width: 1280, height: 900 })
await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
await page.waitForSelector('[data-testid="login-email"]', { timeout: 180_000, polling: 500 })
for (const scheme of ['light', 'dark']) {
  console.log(`\n=== ${scheme.toUpperCase()} ===`)
  const rows = await measure(page, scheme)
  for (const r of rows) {
    if (r.missing) { console.log(`${r.name}: MISSING`); continue }
    console.log(`${r.name}: ${r.fontSize} w${r.fontWeight} color=${r.color} bg=${r.bg} contrast=${r.contrast}`)
  }
}
await browser.close()
