// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso/04 (the account lifecycle discipline, slice 1) —
// the email_verified claim's HONESTY, proven in-process over the REAL
// op + op-accounts routers against a REAL temp SQLite store (the
// id-op-core round-trip posture + id-account-emails' enroll helper):
//
//   ENROLLED    the invite ceremony's completion stamps the address
//               (the kernel's completeEnrollment) — the ID token AND
//               userinfo answer email_verified true;
//   UNVERIFIED  the admin's email edit resets the stamp (an admin-set
//               address never went through the ceremony) — the same
//               round trip answers FALSE on BOTH surfaces (an RP's
//               link-by-verified-email rule can never be fooled by an
//               unproven mailbox), and the account context carries the
//               state honestly (the console banner's source);
//   THE WAY OUT the self-service email change's MAILED completion
//               re-verifies (the token row's delivered_by decides,
//               never a route parameter) — the claim answers true again.
//   THE RESEND  (wave A, the kernel 0.2.4 'verify' kind) the CURRENT
//               primary's own verification: the holder POSTs the resend,
//               the link mails to the address of record (the
//               verify_primary_email copy — never the change copy), the
//               mailed completion stamps the SAME address (nothing
//               moves: no email_changed notice) and the round trip
//               answers true; the already-verified re-POST is the
//               honest 409.
//
// The demo cast stays honestly unverified (fictional mailboxes) — the
// surface-contract golden re-recorded its false deliberately.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-email-verification-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The registry's bootstrap seed: a confidential client (the hub
// instance's shape — the round trip's RP).
const CONFIDENTIAL = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
process.env.OP_CLIENT_SEED = JSON.stringify([CONFIDENTIAL])

import { resetMailerForTest } from '../../server/mailer'
import { startStubMailer, type StubMailer } from '../../e2e/fixtures/stub-mailer'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let stub: StubMailer
let validateIdToken: typeof import('../../server/oidc').validateIdToken
let generatePkce: typeof import('../../server/oidc').generatePkce

const UNA = { email: 'una@example.org', name: 'Una Example', password: 'una has a proper passphrase' }
const UNA_EDITED = 'una.renamed@example.org'
const UNA_NEXT = 'una.next@example.org'
const UNA_RESEND = 'una.resend@example.org' // the wave-A leg's admin re-address (a fresh recipient — the mailer bucket)

/** The fetch adapter the RP's validator runs against: the in-process
 *  app itself (discovery/JWKS ride the real routes). */
const appFetch = (async (input: RequestInfo | URL): Promise<Response> => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
  return app.request(url)
}) as typeof fetch

function bindStubProvider(): void {
  process.env.EMAIL_FROM = 'OIML SMART Identity <no-reply@oimlsmart.org>'
  process.env.MAIL_PROVIDER_URL = `${stub.baseUrl}/emails`
  process.env.MAIL_PROVIDER_KEY = 'stub-mail-key'
  resetMailerForTest()
}

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function passwordLogin(email: string, password: string): Promise<string> {
  const res = await app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.ok, `password login ${email}`).toBe(true)
  await new Promise(r => setTimeout(r, 25)) // the sign-in notice rides beside the answer (TODO.restructure/27)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** Invite + enroll an account; answers { id } (the id-account-emails
 *  helper's shape). */
async function enrollAccount(email: string, name: string, password: string): Promise<{ id: string }> {
  const admin = await demoLogin('admin@oiml.org')
  const invite = await app.request('/api/op/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name }),
  })
  expect(invite.status).toBe(201)
  const { account, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  const res = await app.request(`/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(res.status).toBe(200)
  return { id: account.id }
}

/** The full round trip for the account: authorize → consent → code →
 *  token → userinfo; answers the VALIDATED id-token claims + the
 *  userinfo body (the id-op-core driver's shape). */
async function roundTrip(cookie: string): Promise<{ idToken: Record<string, unknown>; userinfo: Record<string, unknown> }> {
  const pkce = await generatePkce()
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: CONFIDENTIAL.client_id,
    redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
    scope: 'openid profile email',
    state: 'st-1',
    nonce: 'nn-1',
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
    // Force the consent page (a remembered grant would skip it).
    prompt: 'consent',
  })
  const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status, 'authorize redirects to the consent page').toBe(302)
  const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
  const authId = consentUrl.searchParams.get('auth')!
  const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  expect(decide.status, 'the decision records').toBe(200)
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')!

  const token = await app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(CONFIDENTIAL.client_id)}:${encodeURIComponent(CONFIDENTIAL.secret)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      client_id: CONFIDENTIAL.client_id,
      code_verifier: pkce.verifier,
    }),
  })
  expect(token.status, 'the code exchange').toBe(200)
  const tokens = await token.json() as { id_token: string; access_token: string }
  // The RP's real validator consumes the token (the interop proof).
  const idToken = await validateIdToken(tokens.id_token, {
    issuer: ISSUER,
    clientId: CONFIDENTIAL.client_id,
    nonce: 'nn-1',
    jwksUri: `${ISSUER}/jwks.json`,
  }, appFetch)

  const userinfoRes = await app.request(`${ISSUER}/op/userinfo`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  })
  expect(userinfoRes.status, 'userinfo answers').toBe(200)
  const userinfo = await userinfoRes.json() as Record<string, unknown>
  return { idToken: idToken as Record<string, unknown>, userinfo }
}

/** The one link line of a captured email's text body. */
function linkFromEmailText(text: string | undefined): string {
  const link = (text ?? '').split('\n').map(l => l.trim()).find(l => l.startsWith('http'))
  expect(link, 'the email text carries its action link').toBeTruthy()
  return link!
}

beforeAll(async () => {
  // The simulated deployment declares its signing key (identity#7's
  // registration gate — the id-op-core posture).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))

  const oidc = await import('../../server/oidc')
  validateIdToken = oidc.validateIdToken
  generatePkce = oidc.generatePkce
  oidc.clearOidcCaches()

  stub = await startStubMailer({ expectedKey: 'stub-mail-key' })
  bindStubProvider()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpAccountsRouter())
  app = root
  await demoLogin('admin@oiml.org') // the bootstrap seed lands on the first OP request
})

afterAll(async () => {
  await stub.close()
  for (const k of ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY']) delete process.env[k]
  resetMailerForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
  const profileMod = await import('../../server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('TODO.identity-sso/04 — the email_verified claim answers the CURRENT state', () => {
  it('ENROLLED: the invite ceremony verifies the address — the ID token + userinfo answer true', async () => {
    await enrollAccount(UNA.email, UNA.name, UNA.password)
    const cookie = await passwordLogin(UNA.email, UNA.password)
    const { idToken, userinfo } = await roundTrip(cookie)
    expect(idToken.email).toBe(UNA.email)
    expect(idToken.email_verified, 'the ID token carries the enrollment stamp').toBe(true)
    expect(userinfo.email, 'userinfo answers the same address').toBe(UNA.email)
    expect(userinfo.email_verified, 'userinfo carries the same stamp').toBe(true)
  })

  it('UNVERIFIED: the admin-set address resets the stamp — both surfaces answer false', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const account = await store.findUserByEmail(UNA.email)
    expect(account).toBeTruthy()
    const edit = await app.request(`/api/op/accounts/${account!.id}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ email: UNA_EDITED }),
    })
    expect(edit.status, 'the admin edit lands').toBe(200)

    // The state is honest on the account row + the console's context.
    expect((await store.getUserById(account!.id))?.emailVerifiedAt ?? null).toBeNull()
    const cookie = await passwordLogin(UNA_EDITED, UNA.password)
    const context = await app.request('/api/op/account', { headers: { cookie } })
    expect(((await context.json()) as { account: { emailVerifiedAt: string | null } }).account.emailVerifiedAt).toBeNull()

    const { idToken, userinfo } = await roundTrip(cookie)
    expect(idToken.email).toBe(UNA_EDITED)
    expect(idToken.email_verified, 'an unproven mailbox never reads as vouched').toBe(false)
    expect(userinfo.email_verified, 'userinfo answers the same').toBe(false)
  })

  it('THE WAY OUT: the emailed email-change completion re-verifies — the claim answers true again', async () => {
    const cookie = await passwordLogin(UNA_EDITED, UNA.password)
    stub.reset() // earlier sign-in notices are not this leg's subject
    const request = await app.request('/api/op/account/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: UNA_NEXT }),
    })
    expect(request.status).toBe(201)
    expect(((await request.json()) as { delivery: string }).delivery, 'the stub mailer carries the link').toBe('mailer')

    const verificationMails = stub.messages.filter(m => m.to === UNA_NEXT)
    expect(verificationMails).toHaveLength(1)
    const link = linkFromEmailText(verificationMails[0]!.text)
    expect(link).toContain(`${ISSUER}/op/email-change?token=`)
    const complete = await app.request(link.replace(`${ISSUER}/op/email-change?token=`, `${ISSUER}/api/op/email-change/`), { method: 'POST' })
    expect(complete.status).toBe(200)
    expect(await complete.json()).toMatchObject({ ok: true, email: UNA_NEXT, verified: true, kind: 'change' })

    const fresh = await passwordLogin(UNA_NEXT, UNA.password)
    const { idToken, userinfo } = await roundTrip(fresh)
    expect(idToken.email).toBe(UNA_NEXT)
    expect(idToken.email_verified, 'the mailed completion re-verified the mailbox').toBe(true)
    expect(userinfo.email_verified, 'userinfo answers the same').toBe(true)
  })

  it('THE RESEND (wave A): the unverified primary asks for its own link — the mailed verify completion stamps the SAME address', async () => {
    // The administrator re-addresses the account again (the unverified
    // posture the resend exists for).
    const admin = await demoLogin('admin@oiml.org')
    const account = await store.findUserByEmail(UNA_NEXT)
    expect(account).toBeTruthy()
    const edit = await app.request(`/api/op/accounts/${account!.id}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ email: UNA_RESEND }),
    })
    expect(edit.status, 'the admin re-address lands').toBe(200)
    expect((await store.getUserById(account!.id))?.emailVerifiedAt ?? null, 'the re-addressed primary is unverified').toBeNull()

    const cookie = await passwordLogin(UNA_RESEND, UNA.password)
    stub.reset() // the sign-in notices are not this leg's subject

    // The resend: the link mints ONLY on a sent mail, addressed to the
    // CURRENT primary itself.
    const resend = await app.request('/api/op/account/email/verification', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
    })
    expect(resend.status, 'the resend mints + mails').toBe(201)
    expect(await resend.json()).toMatchObject({ email: UNA_RESEND, delivery: 'mailer' })

    const verifyMails = stub.messages.filter(m => m.to === UNA_RESEND)
    expect(verifyMails, 'exactly one link to the address of record').toHaveLength(1)
    expect(verifyMails[0]!.subject ?? '', 'the verify-the-primary copy — never the change copy')
      .toBe('Confirm the email address on your OIML SMART Identity account')
    const link = linkFromEmailText(verifyMails[0]!.text)
    expect(link).toContain(`${ISSUER}/op/email-change?token=`)

    const complete = await app.request(link.replace(`${ISSUER}/op/email-change?token=`, `${ISSUER}/api/op/email-change/`), { method: 'POST' })
    expect(complete.status).toBe(200)
    expect(await complete.json()).toMatchObject({ ok: true, email: UNA_RESEND, verified: true, kind: 'verify' })

    // Nothing moved: the ceremony mails NO email_changed notice.
    expect(stub.messages.filter(m => (m.subject ?? '').includes('was changed')),
      'the verify ceremony never cries "the address changed"').toHaveLength(0)

    const fresh = await passwordLogin(UNA_RESEND, UNA.password)
    const { idToken, userinfo } = await roundTrip(fresh)
    expect(idToken.email).toBe(UNA_RESEND)
    expect(idToken.email_verified, 'the mailed verify completion re-verified the SAME primary').toBe(true)
    expect(userinfo.email_verified, 'userinfo answers the same').toBe(true)

    // The honest 409: an already-verified primary never re-mints.
    const again = await app.request('/api/op/account/email/verification', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: fresh },
    })
    expect(again.status, 'the already-verified resend is the honest conflict').toBe(409)
  })
})
