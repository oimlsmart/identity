# TODO.restructure/24 — the seam diet: the dead verb families out

**Priority:** P2 (cleanliness/DRY — dead code shipped in the Worker
bundle; zero runtime behavior change)
**Status:** AUDIT COMPLETE, the deletion itself OPEN — deliberately:
the automated span-deletion hung on an unbounded comment walk and was
stopped before corrupting the open PR's tree (the files were restored
byte-clean from HEAD, type-check green). The manifest below is the
work; the surgery is a careful follow-up PR, one family at a time,
each brace-bounded and suite-proven.

## The audit (measured 2026-09-12)

The seam interface declares **208 verbs; 65 carry zero references**
outside the store implementations themselves — whole platform families
the wholesale copy brought along:

- **notify** (16): listNotifyRules, putNotifyRule, deleteNotifyRule,
  notifyRulesForEvent, getNotifyPreferences, putNotifyPreferences,
  listNotifyDeliveriesForEvent, getNotifyDelivery, putNotifyDelivery,
  markNotifyDelivery, notifyFailedDeliveries, listNotifyEntityMutes,
  putNotifyEntityMute, deleteNotifyEntityMute, notifyEntityMutesForEvent,
  putNotifyInboxState, listNotifyInboxStates, notifyDigestPending*
- **certificate holders** (8): getCertificateHolderOrg,
  listCertificateHolderOrgs, attributeCertificateHolderOrg,
  create/decide/get/findPending/listCertificateHolderClaims,
  findCertificatesByNumber
- **instrument registrations** (6): create singular+bulk, get,
  list ×3, setLifecycle
- **the events journal** (9): appendEvent(s), getEvent(s), eventsAfter,
  eventsMatching, latestEventSeq, onJournalAppend, changesAfter,
  latestChangeSeq(For)
- **federation peers** (4): get/list/upsert/revokeFederationPeer
- **identity approvals** (3): get/list/upsertIdentityApproval
- **SSO states** (2): putSsoState, consumeSsoState
- **misc** (17): findOrCreateOAuthUser, linkProviderIdentity,
  putEntities, countEntities, listOidcAccessTokens, retireOidcKey,
  getSessionIdTokenHint, wipeWorkflowStores, workflowStoreRowCeiling, …

## The recipe (the follow-up PR)

One FAMILY per commit (notify → certificate holders → instruments →
journal → peers → approvals → sso → misc), each verb deleted from four
sites (the store.ts interface entry, the d1 method, the sqlite module
function, the sqlite.ts wiring + import). Bounds: brace-matched spans
with a hard 200-line ceiling per span, fail-loud on any miss;
vue-tsc + the full suite after every family. The sqlite modules whose
verbs are ALL dead (notify.ts, events.ts, likely parts of entities.ts)
delete as whole files. ~1,500 lines out; the Worker bundle slims.

## Acceptance

The audit re-run answers zero dead verbs; the migration set, the
contract golden, and the 581-test suite unchanged.
