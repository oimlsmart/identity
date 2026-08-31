// Screenshot the sign-in page across width × scheme for the visual wave.
import puppeteer from 'puppeteer'
const BASE = process.argv[2] ?? 'http://localhost:5690'
const OUT = process.argv[3] ?? '/tmp/id-visual'
const browser = await puppeteer.launch({ headless: 'shell', args: ['--no-sandbox'] })
for (const [wName, vp] of [['desktop', { width: 1440, height: 900 }], ['phone', { width: 390, height: 844 }]]) {
  for (const scheme of ['light', 'dark']) {
    const page = await browser.newPage()
    await page.setViewport(vp)
    await page.evaluateOnNewDocument((s) => localStorage.setItem('oiml-theme', s), scheme)
    await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await page.waitForSelector('[data-testid="login-email"]', { timeout: 180_000, polling: 500 })
    await new Promise((r) => setTimeout(r, 1200))
    const file = `${OUT}-${wName}-${scheme}.png`
    await page.screenshot({ path: file })
    console.log(file)
    await page.close()
  }
}
await browser.close()
