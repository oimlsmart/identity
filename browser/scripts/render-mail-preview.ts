// ═══════════════════════════════════════════════════════════════════
// The transactional-email proof loop (TODO.identity/09 redesign): render
// every OP template (EN + FR) to HTML and screenshot each at 1440px with
// headless Chromium, so the redesign is reviewed on PIXELS, not on the
// string. Not a gate — a local review aid (`npx tsx scripts/render-mail-preview.ts`).
//
// The HTML carries the PRODUCTION logo URL (OP_MAIL_LOGO_URL); the
// screenshot intercepts that request and serves the repo's own
// browser/public/brand/ copy, so the pixels prove the exact markup the
// mailer sends. (The separate 200 proof that the identity service serves
// /brand/<file> rides the local stack — see the PR body.)
// ═══════════════════════════════════════════════════════════════════

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import puppeteer, { type Browser } from 'puppeteer'
import { renderOpMail, OP_MAIL_LOGO_URL, type OpMailTemplate, type MailLocale } from '../server/auth/op/mail'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = join(BROWSER_DIR, '.cache', 'mail-preview')
const LOGO_FILE = join(BROWSER_DIR, 'public', 'brand', 'oiml-smart-globe-light.png')

const BASE = {
  product: 'OIML SMART Identity',
  issuer: 'https://id.oimlsmart.org',
  name: 'Willa Example',
  hours: 24,
}
const PARAMS: Record<OpMailTemplate, Record<string, string | number>> = {
  invite: { ...BASE, setupUrl: 'https://id.oimlsmart.org/op/setup?token=9f2c7a1b4d6e8a0c2f5b7d9e1a3c5f70' },
  reset: { ...BASE, setupUrl: 'https://id.oimlsmart.org/op/setup?token=4d6e8a0c2f5b7d9e1a3c5f709f2c7a1b' },
  signin: { ...BASE, when: '2026-08-24 09:41', method: 'GitHub' },
  verify_email: { ...BASE, verifyUrl: 'https://id.oimlsmart.org/op/verify-email?token=7c1a9f2b4d6e8a0c2f5b7d9e1a3c5f70' },
}

const TEMPLATES: OpMailTemplate[] = ['invite', 'reset', 'signin', 'verify_email']
const LOCALES: MailLocale[] = ['en', 'fr']

async function main(): Promise<void> {
  mkdirSync(OUT, { recursive: true })
  const logoBytes = readFileSync(LOGO_FILE)

  const jobs: Array<{ file: string; html: string }> = []
  for (const template of TEMPLATES) {
    for (const locale of LOCALES) {
      const rendered = renderOpMail(template, locale, PARAMS[template])
      const file = join(OUT, `${template}.${locale}.html`)
      writeFileSync(file, rendered.html)
      jobs.push({ file, html: rendered.html })
    }
  }

  const browser: Browser = await puppeteer.launch({
    headless: 'shell',
    protocolTimeout: 120_000,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  })
  try {
    for (const job of jobs) {
      const page = await browser.newPage()
      await page.setViewport({ width: 1440, height: 1000, deviceScaleFactor: 2 })
      await page.setRequestInterception(true)
      page.on('request', (req) => {
        if (req.url() === OP_MAIL_LOGO_URL) {
          void req.respond({ status: 200, contentType: 'image/png', body: logoBytes })
        } else {
          void req.continue()
        }
      })
      await page.goto(`file://${job.file}`, { waitUntil: 'networkidle0', timeout: 60_000 })
      const png = job.file.replace(/\.html$/, '.png')
      await page.screenshot({ path: png, fullPage: true })
      console.log(`shot ${png}`)
      await page.close()
    }
  } finally {
    await browser.close()
  }
  console.log(`rendered ${jobs.length} templates into ${OUT}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
