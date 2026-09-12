# TODO.restructure/06 — the kernel's bulk sign-in-posture + identity-links reads

**CLOSED — path (b) won: TODO.restructure/15 wave 1 re-homed the bulk
reads into identity's OWN store (`server/store/`), the three-route swap
landed, and the three `budgetPerRow` legs were DELETED. The gate proves
zero growth with NO budgets (the full suite 575/575 includes it). The
kernel-side implementation below remains as the reference for the
kernel repo's own cleanup wave (TODO 15 wave 5, owner-coordinated) and
historical record of the proof.

**Priority:** P0 (throughput at row-count scale — "loading users/orgs")
**Status:** KERNEL SIDE COMPLETE + THE CONSUMPTION HALF **PROVEN
LOCALLY** (2026-09-10): the identity tree was pointed at the kernel
working tree via a temporary `npm install --no-save` link (the
kernel exports its TS source, so the link runs as-is); the
consumption swap below landed, the three `budgetPerRow` legs were
DELETED, and the gate answered **33/33 with ZERO budgets declared** —
store-call counts invariant to row count — with the FULL suite
**571/571** green over the linked kernel (byte-compatible answers,
order included). The swap and the de-budgeting were then reverted
exactly (the three files byte-identical to HEAD; node_modules back on
npm 0.2.10, budgets re-honored 102/102) because CI installs from npm:
until the owner releases, the staged diff below stays the landing
copy. The bump + release are the OWNER's acts: the version pin is the
contract, npm publishes ride tags only, and version numbers are never
an engineer's pick.

## Problem

Three list endpoints carry DECLARED per-row store-call budgets
(`browser/src/__tests__/endpoint-scaling.test.ts` legs at :280, :296,
:395) because the kernel seam carried no bulk variant of
`countSignInMethods` / `listIdentityLinks` — on the Worker every call is
a D1 subrequest, so a 500-account registry fires ~1000 per admin visit.

## The kernel half (DONE — proof: typecheck 0, suite 216/216 incl. the
new `test/bulk-signin-posture.test.ts` parity spec)

`oimlsmart/platform-server`:
- seam (`src/store.ts`): `countSignInMethodsBulk(userIds): Promise<Map<id, {password, links, passkeys}>>`
  and `listIdentityLinksBulk(userIds): Promise<Map<id, IdentityLink[]>>`
  — every requested id answers (unknown → zeros/empty, the per-id
  posture); empty request → empty map.
- sqlite (`store/sqlite/op-accounts-store.ts` + `upstream-store.ts`,
  wired in `store/sqlite.ts`): one GROUP BY per underlying table; one
  IN-list read for the links (each account's order preserved).
- D1 (`store/d1.ts`): the three grouped counts ride ONE `db.batch` — a
  single round trip; the links ride one statement.
- No migration (reads only). No compound SELECT (the D1 term-cap rule).

## The consumption half (STAGED — lands with the bump, then the three
`budgetPerRow` legs and their notes are DELETED; the gate then proves
zero growth outright)

1. `GET /api/op/accounts` (`server/routes/op-accounts.ts:679`) — hoist
   the pair above the map:

```ts
const [posture, linksByUser] = await Promise.all([
  store.countSignInMethodsBulk(rows.map(r => r.id)),
  store.listIdentityLinksBulk(rows.map(r => r.id)),
])
const built = rows.map(row => { const methods = posture.get(row.id)!; const links = linksByUser.get(row.id)!; /* unchanged body */ })
```

2. `GET /api/op/registry/users` (`server/routes/op-registry.ts:241`) —
   `listRow` gains the optional `(methods, links)` batch parameters
   (the single-row caller keeps its point reads); the bulk pair is read
   once before the `Promise.all(users.map(...))`.

3. `GET /api/op/dashboard/overview` (`server/routes/op-dashboard.ts:324`) —

```ts
const posture = await store.countSignInMethodsBulk(users.map(u => u.id))
let invited = 0
for (const u of users) if (u.active && u.provider === 'password' && !posture.get(u.id)!.password) invited += 1
```

## Acceptance (after the bump)

`cd browser && ENDPOINT_SCALING_REPORT=1 npx vitest run src/__tests__/endpoint-scaling.test.ts`
— the three legs read growth 0 with NO budget declared; the content
pins stay green (byte-compatible answers, order included — the kernel
spec proves the parity).
