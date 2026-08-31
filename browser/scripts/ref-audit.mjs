// The reference-bar audit: github.com/login + orcid.org/signin computed styles.
import puppeteer from 'puppeteer'

const browser = await puppeteer.launch({ headless: 'shell', args: ['--no-sandbox'] })

async function probe(url, picks) {
  const page = await browser.newPage()
  await page.setViewport({ width: 1280, height: 900 })
  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 60_000 })
    await new Promise((r) => setTimeout(r, 2500))
    const rows = await page.evaluate((picks) => {
      const out = []
      for (const [name, sel] of picks) {
        const el = document.querySelector(sel)
        if (!el) { out.push({ name, missing: true }); continue }
        const cs = getComputedStyle(el)
        out.push({ name, fontSize: cs.fontSize, fontWeight: cs.fontWeight, color: cs.color, fontFamily: cs.fontFamily.slice(0, 60) })
      }
      const bcs = getComputedStyle(document.body)
      out.push({ name: 'BODY', fontSize: bcs.fontSize, fontFamily: bcs.fontFamily.slice(0, 60) })
      return out
    }, picks)
    console.log(`\n=== ${url} ===`)
    for (const r of rows) console.log(r.missing ? `${r.name}: MISSING` : `${r.name}: ${r.fontSize} w${r.fontWeight} ${r.color} [${r.fontFamily}]`)
  } catch (e) {
    console.log(`\n=== ${url} === FAILED: ${e.message.slice(0, 200)}`)
  } finally {
    await page.close()
  }
}

await probe('https://github.com/login', [
  ['username label', 'label[for="login_field"]'],
  ['username input', '#login_field'],
  ['password input', '#password'],
  ['forgot link', 'a[href="/password_reset"]'],
  ['submit', 'input[type="submit"], button[type="submit"]'],
  ['passkey button', '.passkey-signin-button, [data-testid="passkey-sign-in-button"]'],
  ['create account line', '.login-callout, p.create-account-callout'],
])
await probe('https://orcid.org/signin', [
  ['username input', '#username'],
  ['password input', '#password'],
  ['signin button', '#signin-button, button[type="submit"]'],
  ['forgot link', '#forgot-password, a[href*="reset"]'],
  ['register line', '.register-now, a[href*="register"]'],
])
await browser.close()
