# TODO.restructure/25 — the ship

**Priority:** P0 (the program's terminal act)
**Status:** COMPLETE — executed under the owner's thrice-repeated "Do all
of this! Do not hold off" (the WHEN), the tag's WHAT fully determined by
the repo's own convention (date + sequence: `id-v2026.09.12-1`, no tag
this date; the prior tags `id-v2026.09.08-1`/`id-v2026.09.09-2` shipped
the PRE-split code — this one ships the program).

## What this tag carries to the pipeline

Main's head (`1439070`): the kernel-free split (identity owns its store,
migrations, seams — the npm pin gone), the perf arc (hot paths batched,
bulk reads, ZERO scaling budgets), self-registration, the whitelabel
posture (a) with verified branding + federation, the full bilingual
lockstep, the platform-residue pruning, and the seam diet (65 dead
verbs). Gates: vue-tsc, 581/581, both builds, contract golden — and
CI's whole e2e pack green on both merged PRs.

## The pipeline stages (deploy-identity.yml, tag-triggered)

1. contract gate (the op-surface golden) → e2e legs → build
2. deploy-preview → id-preview.oimlsmart.org — **the D1 migrations run
   here**: `0027_notify_mentions_saved` + `0028_entities_certificate_
   number_index` apply to the preview D1 first (the live registry's
   journal stands at 0026 for those two — verified read-only 2026-09-12;
   the files are byte-identical to the pre-split set, so the journal
   continues cleanly; 0027's tables serve the notify family the diet
   pruned from CODE — tables ship unused, the expand-only discipline
   holds)
3. deploy-production → **the cloudflare-identity-production environment
   waits on the OWNER's required reviewers** — the human gate that
   stays the owner's even under "do not hold off"

## The post-deploy verifications (after production approval)

- The issuer stands (`https://id.oimlsmart.org` discovery `issuer`).
- The registry's journal advanced (0027/0028 applied — read-only list).
- Preview parity: id-preview.oimlsmart.org serves the same surface.
