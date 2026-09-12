# TODO.restructure/18 — the kind-projected console nav

**Priority:** P1 · **Status:** COMPLETE (landed inside 17's slice — one
coherent change; recorded separately because it was 16's named gap).

## What landed

`ConsoleChrome.vue`'s admin rail derives from the DEPLOYMENT'S DECLARED
section set (`console.sections` in the profile → /api/config → the
`useConsoleSections()` accessor on the shared one-fetch probe). No
component edit ever branches on an instance kind; the flavors' YAMLs
carry the difference. Undeclared = the full default set (the central
instance, byte-compatible — pinned by id-whitelabel.test.ts's
UNDECLARED leg).
