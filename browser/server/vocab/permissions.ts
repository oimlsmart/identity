// ═══════════════════════════════════════════════════════════════════
// The action-permission catalog (TODO.federation/12).
//
// roles.ts gates SECTIONS (which console a role may enter); THIS module
// gates ACTIONS (what a role may DO once inside): accept an application,
// issue a dispatch, sign a test report, finalize an evaluation report,
// issue a certificate, manage users, …
//
// The catalog is enumerated ONCE here and referenced from three places:
//
//   1. the transition → permission map below (every state-machine edge
//      names the permission(s) its actor must hold — the machines are
//      GENERATED from PRL (primmel-packages/oiml-smart-core/
//      evaluation/state-machines.prl → data/core/evaluation/
//      state-machines.yaml), so the permission annotation lives here in
//      code, keyed by transition identity, NOT in the generated YAML;
//      editing the PRL to carry it would push a platform concern into
//      the program's normative source);
//   2. the server write gate (browser/server/routes/entities.ts refuses
//      a transition write whose actor lacks its permission — honest 403
//      naming the missing permission);
//   3. the UI (v-can / usePermissions disables a denied action and
//      explains which roles hold it).
//
// This module is PLAIN TypeScript: no Vue, no node built-ins — the
// browser bundle, the node server and the Cloudflare Worker all import
// it.
// ═══════════════════════════════════════════════════════════════════

/** The catalog: permission id → a one-line description (the admin UI,
 *  the denial hints and docs/deployment/rbac.md all render from this). */
export const PERMISSION_INFO = {
  // ── the application phase (PD-05) ──
  'application.submit':   { label: 'Submit, resubmit or withdraw an application' },
  'application.review':   { label: 'Review an application (start the review, request changes)' },
  'application.accept':   { label: 'Decide an application (accept / reject)' },
  // ── samples (PD-05 §4.2 custody chain) ──
  'samples.request':      { label: 'Issue the sample request' },
  'samples.register':     { label: 'Register sample receipts and returns' },
  'samples.manage':       { label: 'Manage sample custody (dispatch, recall, return, retain, destroy, dispose)' },
  'samples.ship':         { label: 'Record the shipment of samples (the manufacturer)' },
  'samples.custody':      { label: 'Laboratory sample custody (acknowledge receipt, start and complete testing)' },
  // ── dispatch + the laboratory's work (PD-05 §4.3) ──
  'dispatch.issue':       { label: 'Issue or withdraw a test request (the dispatch)' },
  'dispatch.respond':     { label: 'Accept or decline a test request (the laboratory)' },
  'run.perform':          { label: 'Perform test runs, fill test forms, work test assignments' },
  'tr.sign':              { label: 'Sign a test report (the pinned signature acknowledgment)' },
  'tr.submit':            { label: 'Submit or recall a test report' },
  'tr.review':            { label: 'Review and decide test reports (accept / reject / return)' },
  // ── the evaluation report + the certificate (PD-06/PD-08) ──
  'er.review':            { label: 'Work the evaluation report (open it, record determinations)' },
  'er.finalize':          { label: 'Finalize the evaluation report (the type-evaluation decision)' },
  'certificate.issue':    { label: 'Issue a certificate (create, submit for registration, renew / revise / transfer)' },
  'certificate.register': { label: 'Register a certificate (the BIML registration act)' },
  'certificate.manage':   { label: 'Manage the certificate lifecycle (suspend, reinstate, withdraw, expire, investigate, clear)' },
  // ── the engagement phase (TODO.federation/02 — inquiry → quotation →
  //    agreement → conversion; ISO/IEC 17065 7.2/7.3) ──
  'engagement.manage':    { label: 'Drive the pre-application engagement (issue the quotation, convert to application, decline)' },
  'engagement.respond':   { label: 'Respond to an engagement (sign the agreement, decline, withdraw — the applicant)' },
  // ── the generalized negotiation (TODO.adoption/07 — the engagement
  //    module's kinds: ia_applicant rides the engagement.* pair above;
  //    ia_tl and tl_applicant bring the laboratory in as the quoting
  //    provider, and the dispatch's quote leg lets a laboratory answer a
  //    test request with a quotation) ──
  'negotiation.quote':    { label: 'Quote for work (the provider side: issue a quotation on a negotiation or a dispatched test request — the laboratory)' },
  'negotiation.accept':   { label: 'Accept or decline a quotation for work (the requester side: the Issuing Authority on the dispatch quote leg and on ia_tl negotiations)' },
  // ── records mode (TODO.adoption/02 — the Excel bridge): registering an
  //    offline-produced evaluation / test report / certificate with honest
  //    "registered offline" provenance; the act walks the machines'
  //    declared register_offline entry legs, never a fake history ──
  'records.register':     { label: 'Register an offline-produced evaluation, test report or certificate (records mode)' },
  // ── the scheme's organs + operations (B 18 §5–§7) ──
  'participants.review':  { label: 'Assess participant applications (evidence, RC referral and recommendation)' },
  'participants.decide':  { label: 'Decide participant applications (the MC vote, suspension, reinstatement)' },
  'participants.manage':  { label: 'Manage participant declarations and withdrawals' },
  'operations.manage':    { label: 'Run scheme operations (appeals, complaints, misuse cases)' },
  // ── the ANR lifecycle (TODO.adoption/11 — the OIML-CS utilizer page:
  //    Utilizers/Associates specify Additional National Requirements with
  //    their test procedures; the registry moderates before they go live) ──
  'anr.declare':          { label: 'Declare Additional National Requirements for your country (Utilizer/Associate staff)' },
  'anr.review':           { label: 'Review and decide ANR declarations (the registry moderation)' },
  // ── the payment records (TODO.adoption/09 — money moves outside the
  //    platform; the evidential record lives inside: the IA→OIML-CS
  //    certificate fee raised at issuance (PD-05 §6.2) and the IA↔TL
  //    arrangement invoices; never a payment processor) ──
  'payment.invoice':      { label: 'Raise a payment record (the IA↔TL arrangement invoice; the evidential record only)' },
  'payment.mark_paid':    { label: 'Mark a payment record paid with its settlement reference and evidence' },
  'markings.manage':      { label: 'Manage markings, sealings and calibration records' },
  'verification.perform': { label: 'Perform verification activities (VIML 2.09/2.12–2.14)' },
  // ── the instrument register (TODO.register/03 — the per-serial
  //    registration under a certificate's scope; the executing scope at
  //    the instrument level: the scope check refuses out-of-scope
  //    declarations with the reason) ──
  'serial.register':      { label: 'Register instrument serial numbers under a certificate your organization holds, and mark their lifecycle (out of service, withdrawn)' },
  // ── the instance itself (TODO.federation) ──
  'peers.manage':         { label: 'Manage federation peers (TODO.federation/04)' },
  'instance.settings':    { label: 'Change the instance settings (TODO.federation/01)' },
  'users.manage':         { label: 'Manage the instance’s users and their role assignments' },
  // ── delegated organization administration (TODO.identity/10) ──
  // The ORG-SCOPED twin of users.manage: the organization administrator
  // manages only their own organization's people (server-enforced on the
  // account's org binding — never a wider slice). BIML creates one org
  // admin per REGISTERED participant org; the org admin does the typing.
  'org.users.manage':     { label: 'Manage the users of your own organization (the delegated org admin)' },
} as const

export type ActionPermission = keyof typeof PERMISSION_INFO

/** The enumerated catalog (the integrity test pins map values against it). */
export const ACTION_PERMISSIONS = Object.keys(PERMISSION_INFO) as ActionPermission[]

export function isActionPermission(value: string): value is ActionPermission {
  return value in PERMISSION_INFO
}

// ── The transition → permission map ─────────────────────────────────
// Keyed by transition identity `${machineEntity}:${action}->${to}` —
// the (action, to) pair is the walker's disambiguator (an action name
// alone is not unique across a machine, cf. the certificate's three
// `withdraw` edges), and the permission is an actor property of the
// edge, so same-(action,to) edges from different from-states share one
// entry.
//
// The value is a SET: the write passes when the actor holds ANY listed
// permission. Singletons are the rule; a set appears only where one
// edge has genuinely different drivers — cascade-ridden edges whose
// firing transition belongs to different actors (e.g. a form instance's
// recall rides the laboratory's withdrawal AND the IA's return-to-lab).

export function transitionPermissionKey(machineEntity: string, action: string, to: string): string {
  return `${machineEntity}:${action}->${to}`
}

export const TRANSITION_PERMISSIONS: Record<string, readonly ActionPermission[]> = {
  // application (the applicant's acts vs the IA's desk)
  'application:submit->SUBMITTED': ['application.submit'],
  'application:ia_requests_samples->SAMPLES_REQUESTED': ['samples.request'],
  'application:ia_logs_samples->SAMPLES_RECEIVED': ['samples.register'],
  'application:ia_starts_review->UNDER_REVIEW': ['application.review'],
  'application:ia_accepts->ACCEPTED': ['application.accept'],
  'application:ia_rejects->REJECTED': ['application.accept'],
  'application:ia_requests_changes->CHANGES_REQUESTED': ['application.review'],
  'application:applicant_resubmits->UNDER_REVIEW': ['application.submit'],
  'application:applicant_withdraws->WITHDRAWN': ['application.submit'],
  // records mode (TODO.adoption/02): the registered-offline entry — the
  // application's honest hop into ACCEPTED without a fake walked history.
  'application:register_offline->ACCEPTED': ['records.register'],
  // DEMO_FLOWS wave 1: the lifecycle closure — the IA marks the Evaluation
  // Project COMPLETED once the completion gate's settling conditions all
  // hold (the model's completion_settled guard refuses otherwise); the act
  // is the IA's decision desk on the application, the same family as the
  // accept/reject decisions.
  'application:ia_marks_completed->COMPLETED': ['application.accept'],

  // test_request (the dispatch; TODO.adoption/07's quote leg: the
  // laboratory's quotation response and the IA's commercial decision on it)
  'test_request:ia_issues->ISSUED': ['dispatch.issue'],
  'test_request:lab_accepts->ACCEPTED_BY_LAB': ['dispatch.respond'],
  'test_request:lab_quotes->QUOTED': ['negotiation.quote'],
  'test_request:ia_accepts_quotation->ACCEPTED_BY_LAB': ['negotiation.accept'],
  'test_request:ia_declines_quotation->REJECTED_BY_LAB': ['negotiation.accept'],
  'test_request:lab_declines->REJECTED_BY_LAB': ['dispatch.respond'],
  'test_request:lab_starts_testing->IN_PROGRESS': ['run.perform'],
  'test_request:lab_issues_test_report->COMPLETED': ['tr.submit'],
  'test_request:ia_cancels->WITHDRAWN': ['dispatch.issue'],

  // test_report
  'test_report:lab_submits->SUBMITTED': ['tr.submit'],
  'test_report:ia_starts_review->UNDER_REVIEW': ['tr.review'],
  // DEMO_FLOWS wave 1: the review period's opening on the test report —
  // the IA's TR-review desk (the consultation rides the review class).
  'test_report:ia_opens_consultation->CONSULTATION': ['tr.review'],
  'test_report:ia_accepts->ACCEPTED': ['tr.review'],
  'test_report:ia_rejects->REJECTED': ['tr.review'],
  'test_report:lab_withdraws_for_edit->DRAFT': ['tr.submit'],
  'test_report:ia_returns_to_lab->DRAFT': ['tr.review'],
  // records mode (TODO.adoption/02): the laboratory registers a report it
  // produced offline — enters SUBMITTED, the IA's review stays a real act.
  'test_report:register_offline->SUBMITTED': ['records.register'],

  // form_instance (largely cascade-ridden — the driver sets the entry)
  'form_instance:lab_starts_filling->IN_PROGRESS': ['run.perform'],
  'form_instance:lab_submits_with_report->SUBMITTED': ['run.perform'],
  'form_instance:test_report_issued->LOCKED': ['tr.submit'],
  'form_instance:test_report_recalled->SUBMITTED': ['tr.submit', 'tr.review'],
  'form_instance:ia_accepts->ACCEPTED': ['tr.review'],
  'form_instance:ia_rejects->REJECTED': ['tr.review'],
  'form_instance:ia_reopens->LOCKED': ['tr.review'],
  'form_instance:run_redone->DRAFT': ['run.perform'],

  // evaluation_report
  'evaluation_report:ia_opens_first_tr->IN_REVIEW': ['er.review'],
  // Fired by the TR-review service when the last report is determined —
  // the reviewing officer holds tr.review, the evaluation worker er.review.
  'evaluation_report:last_tr_determined->ALL_TR_REVIEWED': ['tr.review', 'er.review'],
  // DEMO_FLOWS wave 1: the review period's opening — the IA officer's
  // evaluation-work act (the consultation is the ER's review surface).
  'evaluation_report:ia_opens_consultation->CONSULTATION': ['er.review'],
  'evaluation_report:ia_approves->APPROVED': ['er.finalize'],
  'evaluation_report:ia_rejects->REJECTED': ['er.finalize'],
  'evaluation_report:ia_approves_with_conditions->CONDITIONALLY_APPROVED': ['er.finalize'],
  'evaluation_report:ia_reopens->IN_REVIEW': ['er.finalize'],
  // records mode (TODO.adoption/02): the registered-offline entry — one
  // edge per registered verdict (the walker's action-only lookup needs the
  // distinct names), straight from the machine's initial; each edge's
  // cascade SETS the matching judgment (the D37 doctrine).
  'evaluation_report:register_offline_approved->APPROVED': ['records.register'],
  'evaluation_report:register_offline_rejected->REJECTED': ['records.register'],
  'evaluation_report:register_offline_conditionally_approved->CONDITIONALLY_APPROVED': ['records.register'],

  // certificate
  'certificate:submit->PENDING_REGISTRATION': ['certificate.issue'],
  'certificate:register->ACTIVE': ['certificate.register'],
  'certificate:expire->EXPIRED': ['certificate.manage'],
  'certificate:withdraw->WITHDRAWN': ['certificate.manage'],
  'certificate:suspend->SUSPENDED': ['certificate.manage'],
  'certificate:reinstate->ACTIVE': ['certificate.manage'],
  'certificate:investigate->UNDER_INVESTIGATION': ['certificate.manage'],
  'certificate:clear->ACTIVE': ['certificate.manage'],
  'certificate:renew->PENDING_REGISTRATION': ['certificate.issue'],
  'certificate:revise->PENDING_REGISTRATION': ['certificate.issue'],
  'certificate:transfer_ownership->PENDING_REGISTRATION': ['certificate.issue'],
  // TODO.adoption/05: the non-OIML-CS legs. A certificate under an
  // instance-operated scheme has no BIML registration; the issue act
  // walks it into force, and its renew/revise/transfer conclude at the
  // body (back to ACTIVE).
  'certificate:issue->ACTIVE': ['certificate.issue'],
  'certificate:renew->ACTIVE': ['certificate.issue'],
  'certificate:revise->ACTIVE': ['certificate.issue'],
  'certificate:transfer_ownership->ACTIVE': ['certificate.issue'],

  // certificate_registration (DEMO_FLOWS wave 1 — the register's
  // auto-publish doctrine, the program owner's 2026-08-28 decision): the
  // hub-side registration submission lifecycle — the registrant
  // announcement's shell, the signed package's intake verification, the
  // publication, the recorded refusal. All three edges are SYSTEM acts:
  // the intake automation walks them on the verified signed submission
  // (no human gate between verify and publish — the register's trust is
  // in the signature + the receipt machinery; the human review surfaces
  // stay read postures). The map names the desk authority the automation
  // exercises — the same shape the other engine-fired edges ride (the
  // sample_verification projection's transitions name
  // verification.perform).
  'certificate_registration:intake_verifies->SUBMITTED': ['certificate.register'],
  'certificate_registration:auto_publishes->PUBLISHED': ['certificate.register'],
  'certificate_registration:intake_refuses->REFUSED': ['certificate.register'],

  // test_assignment (the laboratory's work items; `omit` rides the IA's
  // dispatch withdrawal cascade)
  'test_assignment:lab_accepts->ACCEPTED': ['run.perform'],
  'test_assignment:start->IN_PROGRESS': ['run.perform'],
  'test_assignment:complete->COMPLETED': ['run.perform'],
  'test_assignment:invalidate->FAILED': ['run.perform'],
  'test_assignment:redo->IN_PROGRESS': ['run.perform'],
  'test_assignment:omit->OMITTED': ['dispatch.issue'],

  // test_run
  'test_run:record_evidence->IN_PROGRESS': ['run.perform'],
  'test_run:complete->COMPLETED': ['run.perform'],
  'test_run:invalidate->INVALIDATED': ['run.perform'],
  'test_run:redo->PLANNED': ['run.perform'],

  // measuring_instrument_sample (the custody chain)
  'measuring_instrument_sample:manufacturer_ships->IN_TRANSIT': ['samples.ship'],
  'measuring_instrument_sample:ia_logs_receipt->RECEIVED': ['samples.register'],
  'measuring_instrument_sample:ia_dispatches_to_lab->IN_TRANSIT': ['samples.manage'],
  'measuring_instrument_sample:lab_acknowledges_receipt->RECEIVED': ['samples.custody'],
  'measuring_instrument_sample:lab_starts_test->IN_TESTING': ['samples.custody'],
  'measuring_instrument_sample:lab_test_complete->TESTING_COMPLETE': ['samples.custody'],
  'measuring_instrument_sample:ia_recalls->IN_TRANSIT': ['samples.manage'],
  'measuring_instrument_sample:ia_logs_return->RECEIVED': ['samples.register'],
  'measuring_instrument_sample:ia_returns_to_manufacturer->RETURNED': ['samples.manage'],
  'measuring_instrument_sample:ia_retains->RETAINED': ['samples.manage'],
  'measuring_instrument_sample:ia_destroys->DESTROYED': ['samples.manage'],
  'measuring_instrument_sample:ia_disposes->DISPOSED': ['samples.manage'],

  // verification_record + sample_verification (the verification pathways;
  // sample_verification is a PROJECTION machine — no same-named store —
  // its transitions fire inside the trigger engine, never over the wire,
  // but the catalog covers it so every declared edge names a permission)
  'verification_record:verification_starts->IN_PROGRESS': ['verification.perform'],
  'verification_record:tests_completed->ASSESSED': ['verification.perform'],
  'verification_record:conformity_passed->PASSED': ['verification.perform'],
  'verification_record:conformity_failed->FAILED': ['verification.perform'],
  'verification_record:marks_applied->MARKED': ['verification.perform'],
  'sample_verification:initial_verification_passed->VERIFIED': ['verification.perform'],
  'sample_verification:validity_elapsed->REVERIFICATION_DUE': ['verification.perform'],
  'sample_verification:invalidating_signal_received->INVALIDATED': ['verification.perform'],
  'sample_verification:subsequent_verification_passed->VERIFIED': ['verification.perform'],

  // engagement (TODO.federation/02's funnel, generalized by
  // TODO.adoption/07 into the negotiation primitive: the provider-side
  // edges are driven by the IA desk on ia_applicant (engagement.manage)
  // and by the laboratory on ia_tl / tl_applicant (negotiation.quote);
  // the requester-side edges by the applicant (engagement.respond) and
  // by the Issuing Authority on ia_tl (negotiation.accept). The
  // pending-external legs may be recorded from EITHER party's desk.
  'engagement:provider_issues_quotation->QUOTED': ['engagement.manage', 'negotiation.quote'],
  'engagement:agreement_signed->AGREED': ['engagement.manage', 'engagement.respond', 'negotiation.quote', 'negotiation.accept'],
  'engagement:convert_to_application->CONVERTED': ['engagement.manage'],
  'engagement:provider_declines->DECLINED': ['engagement.manage', 'negotiation.quote'],
  'engagement:requester_declines->DECLINED': ['engagement.respond', 'negotiation.accept'],
  'engagement:requester_withdraws->WITHDRAWN': ['engagement.respond', 'negotiation.accept'],
  'engagement:park_external->PENDING_EXTERNAL': ['engagement.manage', 'engagement.respond', 'negotiation.quote', 'negotiation.accept'],
  'engagement:external_agreement_recorded->AGREED': ['engagement.manage', 'engagement.respond', 'negotiation.quote', 'negotiation.accept'],
  'engagement:external_decline_recorded->DECLINED': ['engagement.manage', 'engagement.respond', 'negotiation.quote', 'negotiation.accept'],

  // participant_application + participant_declaration (the CS organs)
  'participant_application:competence_evidence_recorded->ASSESSMENT': ['participants.review'],
  'participant_application:referred_to_rc->RC_REVIEW': ['participants.review'],
  'participant_application:rc_recommendation_recorded->MC_VOTE': ['participants.review'],
  'participant_application:mc_approves->DECLARATION_PENDING': ['participants.decide'],
  'participant_application:mc_rejects->REJECTED': ['participants.decide'],
  'participant_application:declaration_signed->ACTIVE': ['participants.manage'],
  'participant_application:mc_suspends->SUSPENDED': ['participants.decide'],
  'participant_application:mc_reinstates->ACTIVE': ['participants.decide'],
  'participant_application:participant_withdraws->WITHDRAWN': ['participants.manage'],
  'participant_declaration:sign->signed': ['participants.manage'],
  'participant_declaration:amend->draft': ['participants.manage'],
  'participant_declaration:suspend->suspended': ['participants.manage'],
  'participant_declaration:reinstate->signed': ['participants.manage'],
  'participant_declaration:withdraw->withdrawn': ['participants.manage'],

  // anr_declaration (TODO.adoption/11 — the Utilizer/Associate declares,
  // the CS registry moderates; amendment/promotion re-enters review)
  'anr_declaration:submit_for_review->SUBMITTED': ['anr.declare'],
  'anr_declaration:cs_approves->APPROVED': ['anr.review'],
  'anr_declaration:cs_rejects->REJECTED': ['anr.review'],
  'anr_declaration:revise->DRAFT': ['anr.declare'],
  'anr_declaration:amend->DRAFT': ['anr.declare'],
  'anr_declaration:withdraw->WITHDRAWN': ['anr.declare'],

  // payment_record (TODO.adoption/09 — the payer records the settlement;
  // the hub's collection desk holds it too, B 18:2018 §9 b))
  'payment_record:mark_paid->MARKED_PAID': ['payment.mark_paid'],

  // appeals / complaints / misuse (the scheme-operations console)
  'appeal_case:information_circulated->CIRCULATED': ['operations.manage'],
  'appeal_case:boa_considers->CONSIDERED': ['operations.manage'],
  'appeal_case:boa_decides->DECIDED': ['operations.manage'],
  'appeal_case:rule_inadmissible->INADMISSIBLE': ['operations.manage'],
  'complaint_case:investigation_opened->INVESTIGATION': ['operations.manage'],
  'complaint_case:complaint_upheld->UPHELD': ['operations.manage'],
  'complaint_case:complaint_dismissed->DISMISSED': ['operations.manage'],
  'misuse_case:owner_warned->WARNED': ['operations.manage'],
  'misuse_case:case_closed->CLOSED': ['operations.manage'],
  'misuse_case:biml_deregisters->DEREGISTERED': ['operations.manage'],

  // markings / sealings / calibration records (module B)
  'marking:marking_affixed->AFFIXED': ['markings.manage'],
  'marking:marking_inspected->INSPECTED': ['markings.manage'],
  'marking:marking_superseded->SUPERSEDED': ['markings.manage'],
  'sealing:sealing_affixed->AFFIXED': ['markings.manage'],
  'sealing:sealing_inspected->INSPECTED': ['markings.manage'],
  'sealing:sealing_superseded->SUPERSEDED': ['markings.manage'],
  'calibration_record:calibration_record_affixed->AFFIXED': ['markings.manage'],
  'calibration_record:calibration_record_inspected->INSPECTED': ['markings.manage'],
  'calibration_record:calibration_record_superseded->SUPERSEDED': ['markings.manage'],
}

/** The permissions an edge requires (undefined when the edge is unmapped
 *  — the integrity test makes that impossible; the server gate treats it
 *  as a map bug and refuses loudly, never silently allows). */
export function permissionsForTransition(
  machineEntity: string,
  action: string,
  to: string,
): readonly ActionPermission[] | undefined {
  return TRANSITION_PERMISSIONS[transitionPermissionKey(machineEntity, action, to)]
}

// ── The store-side views of the map ──────────────────────────────────

/** entity store name → machine entity (the snake_case machine map key).
 *  Stores absent here have no lifecycle machine — writes to them stay
 *  org-gated only (audit events, notifications, reference data). */
export const STORE_MACHINES: Record<string, string> = {
  applications: 'application',
  engagements: 'engagement',
  testRequests: 'test_request',
  testReports: 'test_report',
  formInstances: 'form_instance',
  evaluationReports: 'evaluation_report',
  certificates: 'certificate',
  // DEMO_FLOWS wave 1: the register's registration submissions are
  // machinated too (the intake-verify → auto-publish chain); the generic
  // write path gates status writes on the machine's declared edges.
  certificateRegistrations: 'certificate_registration',
  testAssignments: 'test_assignment',
  testRuns: 'test_run',
  measuringInstrumentSamples: 'measuring_instrument_sample',
  verificationRecords: 'verification_record',
  participantApplications: 'participant_application',
  participantDeclarations: 'participant_declaration',
  anrDeclarations: 'anr_declaration',
  paymentRecords: 'payment_record',
  appeals: 'appeal_case',
  complaints: 'complaint_case',
  misuseCases: 'misuse_case',
  markings: 'marking',
  sealings: 'sealing',
  calibrationRecords: 'calibration_record',
}

/** CREATION gates: the stores where even creating a row is a named
 *  action (a certificate draft IS the issuance act — PD-08). Everywhere
 *  else creation stays org-gated data entry (a DRAFT application, a
 *  draft dispatch). */
export const CREATION_PERMISSIONS: Record<string, readonly ActionPermission[]> = {
  certificates: ['certificate.issue'],
  // Declaring an ANR is a named act (TODO.adoption/11): even the DRAFT
  // record carries the declarer's name and country.
  anrDeclarations: ['anr.declare'],
  // Raising a payment record is the invoicing act (TODO.adoption/09); the
  // certificate-fee record rides the issuance act that raises it, so the
  // issuing officer's certificate.issue passes the gate as well.
  paymentRecords: ['payment.invoice', 'certificate.issue'],
  // TODO.adoption/05: defining a scheme is an instance-settings act (the
  // registry rides the deployment's own control surface); a certificate's
  // document list is maintained by the certificate's issuers.
  operatedSchemes: ['instance.settings'],
  certificateDocumentLists: ['certificate.issue'],
}

/** FIELD guards: a field going unset → set is the act (the test
 *  report's pinned signature acknowledgment is the SIGNING act — it
 *  changes no status, so the transition map never sees it). */
export const FIELD_GUARD_PERMISSIONS: Record<string, Record<string, readonly ActionPermission[]>> = {
  testReports: { signature_acknowledgment: ['tr.sign'] },
}

// ── The store-wide write gate (the 2026-09-07 security cone audit's
//    F2) ────────────────────────────────────────────────────────────
// ORG_FIELDS (store.ts) cones the org-fielded workflow stores and
// STORE_MACHINES + CREATION/FIELD_GUARD gate the machinated ones — but
// both leave holes the audit named: a store with NO org fields and NO
// machine answered a generic PUT/DELETE from ANY authenticated role
// (viewer included), and a machinated store gated only its status moves
// — a field update without a status change, or a creation the CREATION
// map does not name, computed NO requirement at all. The worst
// amplification: organizations carries the submission_public_keys the
// intake's signature check trusts.
//
// THIS map is the write side's store-class declaration for the stores
// the org cone cannot carry: EVERY generic write to a listed store
// (create, in-place update, delete — status change or not) requires the
// actor to hold ANY of the named permissions, on top of every other
// gate that fires (the machine's transitions, the creation acts, the
// field guards). The consumer's entities router composes the classes:
// org-fielded → the org cone; catalog → the catalog write gate;
// machinated → the machine's edges; listed here → this gate; NONE of
// those → the generic write refuses outright (deny-by-default). The
// gate is uniform over roles: the platform roles pass because their map
// grants the permission, never because the gate looks away.

/** The store-wide write requirements (store → any-of permission set).
 *  The assignments follow the app's actual write callers, audited
 *  2026-09-07:
 *
 *  - the participants register (PD-03/PD-04/PD-08/PD-09): the Executive
 *    Secretary administers (participants.manage), the RC assesses
 *    (participants.review), the MC votes (participants.decide);
 *  - the scheme-operations records (B 18 §7 — appeals, complaints,
 *    misuse, deregistrations) are the operations console's;
 *  - the §15.8 registered copies record at the registration act (the
 *    IA's local register-with-BIML fallback holds certificate.register)
 *    and at the operations console's corrections;
 *  - the ANR validation letters record at issuance (the issuing
 *    officer's certificate.issue) and at the operations console;
 *  - the ANR declarations: the Utilizer/Associate staffer declares
 *    (anr.declare), the registry moderates (anr.review) — the DRAFT's
 *    in-place edits ride the declarer's permission;
 *  - the instrument register's parties (organizations, manufacturers)
 *    are instance-settings/registry records — organizations in
 *    particular carries submission_public_keys, the intake signature
 *    trust root, so its writes are the instance's own administration;
 *    the manufacturer org rows are created at application intake (the
 *    wizard's quick-create, the IA desk's white-gloves entry);
 *  - the per-model determination records are the evaluation desk's
 *    (er.review / the TR review that stamps them);
 *  - the lab's work records (form instances, verification records, the
 *    module-B markings/sealings/calibration records) ride their work
 *    permissions; the IA's review desks write form instances on the
 *    review/reopen legs;
 *  - the certificate's document lists and annexes are the issuers'. */
export const STORE_WRITE_PERMISSIONS: Record<string, readonly ActionPermission[]> = {
  organizations: ['instance.settings'],
  manufacturers: ['application.submit', 'application.review', 'instance.settings'],
  experts: ['participants.manage'],
  utilizers: ['participants.manage'],
  associates: ['participants.manage'],
  categorySchemes: ['participants.manage'],
  approvalVotes: ['participants.decide'],
  competenceEvidence: ['participants.review', 'participants.manage'],
  participantApplications: ['participants.review', 'participants.manage'],
  participantDeclarations: ['participants.manage'],
  operatedSchemes: ['instance.settings'],
  certificateDocumentLists: ['certificate.issue'],
  certificateAnnexes: ['certificate.issue', 'certificate.manage'],
  registeredCopies: ['certificate.register', 'operations.manage'],
  validationLetters: ['certificate.issue', 'operations.manage'],
  deregistrations: ['operations.manage'],
  appeals: ['operations.manage'],
  complaints: ['operations.manage'],
  misuseCases: ['operations.manage'],
  anrDeclarations: ['anr.declare', 'anr.review'],
  testReportDeterminations: ['tr.review', 'er.review'],
  formInstances: ['run.perform', 'tr.review', 'er.review'],
  verificationRecords: ['verification.perform'],
  certificateRegistrations: ['certificate.register'],
  markings: ['markings.manage'],
  sealings: ['markings.manage'],
  calibrationRecords: ['markings.manage'],
}
