// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso/04 slice D — the security notices' TRIGGERS, proven
// in-process over the REAL op / op-accounts / op-factors / op-mfa /
// op-upstream routers against a REAL temp SQLite store, with the stub
// mail provider (the id-email-verification posture) and the stub IdP
// (the id-upstream posture) on loopback:
//
//   PASSWORD   the enrollment completion AND the console change mail
//              'password_changed' (one copy for both ceremonies);
//   EMAIL      the change completion mails 'email_changed' to the NEW
//              primary (the fan-out) AND the OLD address directly (the
//              mailbox that stopped being the address of record);
//   FACTORS    TOTP enroll/revoke mail 'factor_enrolled'/'factor_revoked'
//              with the user-chosen name in the localized label; the
//              first-factor recovery auto-generation sends NOTHING extra;
//              the recovery-codes regenerate mails the recovery label;
//   RECOVERY   a recovery-code sign-in mails 'recovery_code_used' INSTEAD
//              of the generic sign-in notice (exactly one mail for the
//              entry);
//   ROLES      a non-empty client-roles grant mails
//              'client_roles_granted' (the registry client's display
//              name); the explicit-empty set + the clear never mail;
//   LINKS      the upstream link/unlink mail 'linked_method_added' /
//              'linked_method_removed' (the provider's display name);
//   LOCALE     MAIL_LOCALE=fr renders the French catalog on the trigger.
//
// Every notice's text carries the reset pointer (the sign-in page's
// "Forgot your password?" — `${ISSUER}/`). The assertions read the
// captured mail's subject/text (the stub's CapturedMail carries no
// template field — the copy IS the proof).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-security-notices-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// Slice C's ladder compresses to instant — the legs sign in repeatedly.
process.env.OP_LOGIN_BACKOFF_BASE_MS = '1'

// The registry's bootstrap seed: the client-roles leg's assignable client.
const CONFIDENTIAL = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
process.env.OP_CLIENT_SEED = JSON.stringify([CONFIDENTIAL])

import { resetMailerForTest } from '@oimlsmart/platform-server/mailer'
import { startStubMailer, type StubMailer } from '../../e2e/fixtures/stub-mailer'
import { totpAtStep } from '../../server/auth/op/totp'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let stub: StubMailer
let idp: import('../../e2e/fixtures/stub-idp').StubIdp

const IDP_CLIENT_ID = 'oiml-smart-op'
const IDP_SECRET = 'fixture-idp-secret'

const PRODUCT = 'OIML SMART Identity'

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

/** The password sign-in, answering the status + session cookie + body
 *  (a factored account's answer is the pending challenge, no cookie). */
async function passwordLogin(email: string, password: string): Promise<{ status: number; cookie: string | null; body: Record<string, unknown> }> {
  const res = await app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  const setCookie = res.headers.get('set-cookie')
  return { status: res.status, cookie: setCookie ? setCookie.split(';')[0]! : null, body: await res.json() as Record<string, unknown> }
}

/** Invite + enroll an account; answers { id } + the session cookie the
 *  completion sets. */
async function enrollAccount(email: string, name: string, password: string): Promise<{ id: string; cookie: string }> {
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
  return { id: account.id, cookie: res.headers.get('set-cookie')!.split(';')[0]! }
}

function currentCode(secret: string): Promise<string> {
  return totpAtStep(secret, Math.floor(Date.now() / 1000 / 30))
}

/** The captured mails matching a subject, in arrival order. */
function mailsWithSubject(subject: string): Array<{ to?: string; text?: string; html?: string }> {
  return stub.messages.filter(m => m.subject === subject)
}

/** The one link line of a captured email's text body. */
function linkFromEmailText(text: string | undefined): string {
  const link = (text ?? '').split('\n').map(l => l.trim()).find(l => l.startsWith('http'))
  expect(link, 'the email text carries its action link').toBeTruthy()
  return link!
}

/** Every notice carries the reset pointer to the sign-in page. */
function expectResetPointer(text: string | undefined): void {
  expect(text, 'the notice text carries the "was this you?" reset pointer').toContain(`${ISSUER}/`)
}

/** Enroll a TOTP factor on the account; answers the enrollment + the
 *  first-factor recovery set. */
async function enrollTotp(cookie: string, name: string): Promise<{ id: string; secret: string; recoveryCodes: string[] }> {
  const start = await app.request('/api/op/account/factors/totp', {
    method: 'POST', headers: { 'content-type': 'application/json', cookie },
  })
  expect(start.status).toBe(201)
  const enrollment = await start.json() as { id: string; secret: string }
  const verify = await app.request(`/api/op/account/factors/totp/${enrollment.id}/verify`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ code: await currentCode(enrollment.secret), name }),
  })
  expect(verify.status).toBe(200)
  const body = await verify.json() as { recoveryCodes: string[] | null }
  expect(body.recoveryCodes, 'the first factor lands the recovery set').toHaveLength(10)
  return { ...enrollment, recoveryCodes: body.recoveryCodes! }
}

/** Drive the OP→stub-IdP round trip over real HTTP (the id-upstream
 *  helper's shape): the OP's 302 to the stub's authorize, the stub's
 *  consent shortcut (?user=), the 302 back to the OP's callback. */
async function runFlow(startUrl: string, user: string, cookie?: string): Promise<Response> {
  const start = await app.request(`${ISSUER}${startUrl}`, { headers: cookie ? { cookie } : {}, redirect: 'manual' } as RequestInit)
  expect(start.status, `the flow start ${startUrl}`).toBe(302)
  const authorizeUrl = start.headers.get('location')!
  expect(authorizeUrl.startsWith(`${idp.issuer}/authorize?`)).toBe(true)
  const params = new URL(authorizeUrl).searchParams
  const complete = await fetch(`${idp.issuer}/authorize/complete?${params.toString()}&user=${user}`, { redirect: 'manual' })
  expect(complete.status, 'the stub IdP issues the code').toBe(302)
  const callbackUrl = complete.headers.get('location')!
  return app.request(callbackUrl, { headers: cookie ? { cookie } : {}, redirect: 'manual' } as RequestInit)
}

beforeAll(async () => {
  // The simulated deployment declares its signing key (the id-op-core posture).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))

  stub = await startStubMailer({ expectedKey: 'stub-mail-key' })
  bindStubProvider()

  // The upstream stub (real HTTP on loopback) + its registry row.
  const { startStubIdp } = await import('../../e2e/fixtures/stub-idp')
  idp = await startStubIdp()
  process.env.FIXTURE_IDP_SECRET = IDP_SECRET

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createOpFactorsRouter } = await import('../../server/routes/op-factors')
  const { createOpMfaRouter } = await import('../../server/routes/op-mfa')
  const { createOpUpstreamRouter } = await import('../../server/routes/op-upstream')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpAccountsRouter())
  root.route('/', createOpFactorsRouter())
  root.route('/', createOpMfaRouter())
  root.route('/', createOpUpstreamRouter())
  app = root

  await store.upsertIdentityProvider({
    id: 'fixture-idp', kind: 'oidc', displayName: 'Fixture IdP', brandMark: 'oidc',
    issuer: idp.issuer, clientId: IDP_CLIENT_ID, clientSecretRef: 'env:FIXTURE_IDP_SECRET', enabled: true,
  })

  await demoLogin('admin@oiml.org') // the bootstrap seed lands on the first OP request
})

afterAll(async () => {
  await stub.close()
  await idp?.close()
  for (const k of ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY', 'MAIL_LOCALE']) delete process.env[k]
  resetMailerForTest()
  rmSync(TMP, { recursive: true, force: true })
  for (const k of ['OP_ISSUER', 'OP_SIGNING_KEY', 'OP_CLIENT_SEED', 'DATABASE_PATH', 'OP_LOGIN_BACKOFF_BASE_MS', 'FIXTURE_IDP_SECRET']) delete process.env[k]
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('TODO.identity-sso/04 slice D — the security notices fire on their triggers', () => {
  it('PASSWORD: the enrollment completion mails password_changed', async () => {
    stub.reset()
    await enrollAccount('pat@example.org', 'Pat Password', 'pat has a proper passphrase')
    const notices = mailsWithSubject(`Your ${PRODUCT} password was set or changed`)
    expect(notices).toHaveLength(1)
    expect(notices[0]!.to).toBe('pat@example.org')
    expectResetPointer(notices[0]!.text)
  })

  it('PASSWORD: the console change mails password_changed again', async () => {
    const login = await passwordLogin('pat@example.org', 'pat has a proper passphrase')
    expect(login.cookie).toBeTruthy()
    stub.reset()
    const change = await app.request('/api/op/account/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: login.cookie! },
      body: JSON.stringify({ current: 'pat has a proper passphrase', next: 'pat has a fresh passphrase' }),
    })
    expect(change.status).toBe(200)
    const notices = mailsWithSubject(`Your ${PRODUCT} password was set or changed`)
    expect(notices).toHaveLength(1)
    expect(notices[0]!.to).toBe('pat@example.org')
    expectResetPointer(notices[0]!.text)
  })

  it('EMAIL: the change completion mails the new primary AND the old address', async () => {
    await enrollAccount('elsa@example.org', 'Elsa Email', 'elsa has a proper passphrase')
    const login = await passwordLogin('elsa@example.org', 'elsa has a proper passphrase')
    const request = await app.request('/api/op/account/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: login.cookie! },
      body: JSON.stringify({ email: 'elsa.next@example.org' }),
    })
    expect(request.status).toBe(201)
    const verificationMail = stub.messages.find(m => m.to === 'elsa.next@example.org')
    const link = linkFromEmailText(verificationMail?.text)
    stub.reset()
    const complete = await app.request(link.replace(`${ISSUER}/op/email-change?token=`, `${ISSUER}/api/op/email-change/`), { method: 'POST' })
    expect(complete.status).toBe(200)
    expect(await complete.json()).toMatchObject({ ok: true, kind: 'change' })

    const notices = mailsWithSubject(`Your ${PRODUCT} email address was changed`)
    expect(notices.map(m => m.to).sort(), 'the fan-out reaches the new primary; the direct send reaches the old address')
      .toEqual(['elsa.next@example.org', 'elsa@example.org'])
    for (const notice of notices) {
      expect(notice.text).toContain('elsa@example.org')
      expect(notice.text).toContain('elsa.next@example.org')
      expectResetPointer(notice.text)
    }
  })

  it('FACTORS: TOTP enroll + revoke mail the factor notices (the first-factor recovery set sends nothing extra)', async () => {
    const { cookie } = await enrollAccount('tova@example.org', 'Tova Totp', 'tova has a proper passphrase')
    stub.reset()
    const enrollment = await enrollTotp(cookie, 'Tova’s phone')
    // EXACTLY one mail: the enroll notice — the auto-generated recovery
    // set rides it (no extra mail).
    const added = mailsWithSubject(`A new sign-in factor was added to your ${PRODUCT} account`)
    expect(added).toHaveLength(1)
    expect(added[0]!.to).toBe('tova@example.org')
    expect(added[0]!.text).toContain('Authenticator app "Tova’s phone"')
    expectResetPointer(added[0]!.text)

    stub.reset()
    const revoke = await app.request(`/api/op/account/factors/totp/${enrollment.id}`, {
      method: 'DELETE', headers: { cookie },
    })
    expect(revoke.status).toBe(200)
    const removed = mailsWithSubject(`A sign-in factor was removed from your ${PRODUCT} account`)
    expect(removed).toHaveLength(1)
    expect(removed[0]!.text).toContain('Authenticator app "Tova’s phone"')
    expectResetPointer(removed[0]!.text)
  })

  it('FACTORS: the recovery-codes regenerate mails the recovery label', async () => {
    const { cookie } = await enrollAccount('ruth@example.org', 'Ruth Recovery', 'ruth has a proper passphrase')
    await enrollTotp(cookie, 'Ruth’s phone')
    stub.reset()
    const regen = await app.request('/api/op/account/factors/recovery-codes', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    expect(regen.status).toBe(200)
    const notices = mailsWithSubject(`A new sign-in factor was added to your ${PRODUCT} account`)
    expect(notices).toHaveLength(1)
    expect(notices[0]!.text).toContain('A fresh set of recovery codes (the previous set stopped working)')
    expectResetPointer(notices[0]!.text)
  })

  it('RECOVERY: a recovery-code sign-in mails recovery_code_used INSTEAD of the generic sign-in notice', async () => {
    const { cookie } = await enrollAccount('vera@example.org', 'Vera Verify', 'vera has a proper passphrase')
    const { recoveryCodes } = await enrollTotp(cookie, 'Vera’s phone')
    await app.request('/api/auth/signout', { method: 'POST', headers: { cookie } })
    const login = await passwordLogin('vera@example.org', 'vera has a proper passphrase')
    expect(login.body.mfaRequired).toBe(true)

    stub.reset()
    const done = await app.request('/api/op/login/mfa/recovery', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: login.body.mfaToken, code: recoveryCodes[0] }),
    })
    expect(done.status).toBe(200)
    const recoveryNotices = mailsWithSubject(`A recovery code was used to sign in to your ${PRODUCT} account`)
    expect(recoveryNotices, 'the specialized notice fires').toHaveLength(1)
    expect(recoveryNotices[0]!.to).toBe('vera@example.org')
    expectResetPointer(recoveryNotices[0]!.text)
    // …and the generic sign-in notice did NOT ride the same entry.
    expect(mailsWithSubject(`New sign-in to your ${PRODUCT} account`)).toHaveLength(0)
    expect(stub.messages).toHaveLength(1)
  })

  it('ROLES: a non-empty grant mails client_roles_granted; the empty set + the clear never mail', async () => {
    const { id } = await enrollAccount('rex@example.org', 'Rex Roles', 'rex has a proper passphrase')
    const admin = await demoLogin('admin@oiml.org')
    stub.reset()
    const grant = await app.request(`/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['cs_admin'] }),
    })
    expect(grant.status).toBe(200)
    const notices = mailsWithSubject(`New access was granted on your ${PRODUCT} account`)
    expect(notices).toHaveLength(1)
    expect(notices[0]!.to).toBe('rex@example.org')
    expect(notices[0]!.text).toContain('OIML SMART platform hub')
    expect(notices[0]!.text).toContain('cs_admin')
    expectResetPointer(notices[0]!.text)

    stub.reset()
    const emptied = await app.request(`/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: [] }),
    })
    expect(emptied.status).toBe(200)
    const cleared = await app.request(`/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'DELETE', headers: { cookie: admin },
    })
    expect(cleared.status).toBe(200)
    expect(mailsWithSubject(`New access was granted on your ${PRODUCT} account`), 'restoring a posture never mails').toHaveLength(0)
  })

  it('LINKS: the upstream link + unlink mail linked_method_added / linked_method_removed', async () => {
    const { cookie } = await enrollAccount('lena@example.org', 'Lena Links', 'lena has a proper passphrase')
    stub.reset()
    const linked = await runFlow('/op/upstream/fixture-idp/link', 'ada', cookie)
    expect(linked.status).toBe(302)
    expect(linked.headers.get('location')).toBe(`${ISSUER}/op/account?linked=fixture-idp`)
    const added = mailsWithSubject(`A sign-in method was linked to your ${PRODUCT} account`)
    expect(added).toHaveLength(1)
    expect(added[0]!.to).toBe('lena@example.org')
    expect(added[0]!.text).toContain('Fixture IdP')
    expect(added[0]!.text).toContain('ada@example.org')
    expectResetPointer(added[0]!.text)

    stub.reset()
    const unlink = await app.request(`${ISSUER}/api/op/account/links/fixture-idp`, { method: 'DELETE', headers: { cookie } })
    expect(unlink.status).toBe(200)
    const removed = mailsWithSubject(`A sign-in method was removed from your ${PRODUCT} account`)
    expect(removed).toHaveLength(1)
    expect(removed[0]!.to).toBe('lena@example.org')
    expect(removed[0]!.text).toContain('Fixture IdP')
    expect(removed[0]!.text).toContain('stub-ada')
    expectResetPointer(removed[0]!.text)
  })

  it('LOCALE: MAIL_LOCALE=fr renders the French catalog on the trigger', async () => {
    // A fresh address (the mailer's per-recipient rate limit: pat's
    // mailbox already holds its budget from the earlier legs).
    await enrollAccount('france@example.org', 'France Locale', 'france has a proper passphrase')
    const login = await passwordLogin('france@example.org', 'france has a proper passphrase')
    expect(login.cookie).toBeTruthy()
    stub.reset()
    process.env.MAIL_LOCALE = 'fr'
    try {
      const change = await app.request('/api/op/account/password', {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: login.cookie! },
        body: JSON.stringify({ current: 'france has a proper passphrase', next: 'france has a fresh passphrase' }),
      })
      expect(change.status).toBe(200)
      const notices = mailsWithSubject(`Votre mot de passe ${PRODUCT} a été défini ou changé`)
      expect(notices).toHaveLength(1)
      expect(notices[0]!.to).toBe('france@example.org')
      expectResetPointer(notices[0]!.text)
    } finally {
      delete process.env.MAIL_LOCALE
      resetMailerForTest()
    }
  })
})
