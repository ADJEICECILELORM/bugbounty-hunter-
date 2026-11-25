# Project 001 — Mission Progress

## Mission 004 — Inventory-to-Investigation Planner: complete

- Added deterministic, scope-checked task planning for stored endpoint inventory, including duplicate detection, valid dependencies, task/LLM budget checks, and deferral when inventory work is incomplete.
- Tests: planner, supervisor, task, research, and collector focus — 108 passed; compileall and `git diff --check` passed.
- Files: `orchestration/inventory_planner.py`, `tests/test_inventory_planner.py`, `ARCHITECTURE.md`, `NEXT_STEPS.md`, `CLINE_HANDOFF.md`.
- Limitations: planning consumes stored inventory only; collection is a separate explicit task. `hypothesis_review` is manual.

## Mission 005 — Research and Recon Integration: complete

- Added task dispatch for existing passive DNS reconnaissance and offline researcher briefs. Recon requires the caller's URL authorizer and still checks stored program scope; brief generation makes no network or LLM call.
- Tests: research workflow, endpoint inventory collector, task runner, verification plan input, and supervisor focus — 61 passed.
- Files: `verification/investigation_tasks.py`, `orchestration/task_runner.py`, `tests/test_investigation_tasks.py`, `tests/test_task_runner.py`.
- Limitations: endpoint inventory collection remains a separately authorized task; recon output depends on resolver responses and may be partial.

## Mission 006 — Verification Handoff: complete

- Added bounded transient JSON plan input bound to one hypothesis, generic validation errors, explicit approval and lab-mode gates, single-verification-per-invocation behavior, and suppression of sensitive verification error details in task events/results.
- Tests: verification/task/supervisor/pipeline/evidence focus — 77 passed; the plan-input and task-runner suites pass.
- Files: `verification/plan_input.py`, `verification/run_hypothesis_verification.py`, `tests/test_verification_plan_input.py`, `tests/test_run_hypothesis_verification.py`, both operator scripts, `orchestration/task_runner.py`, `tests/test_task_runner.py`, `tests/test_supervised_cycle.py`.
- Limitations: the existing verifier is lab-only; this work does not make arbitrary production verification safe or authorize it.

## Mission 007 — Supervised Execution: complete

- The supervised cycle now plans stored inventory into research tasks before dispatch, previews proposals without writes, stops at the first failure, refuses verification without transient plan and approval, and blocks on stuck tasks. The CLI prints proposals and stops after a verification refusal.
- Focused planner/task/supervisor/plan-input tests: 92 passed; the final end-to-end focused set also passes.
- Files: `orchestration/inventory_planner.py`, `orchestration/supervised_cycle.py`, `scripts/run_supervised_investigation.py`, `tests/test_inventory_planner.py`, `tests/test_supervised_cycle.py`.
- Limitations: up to five cycles per invocation; no background scheduler. `hypothesis_review` is intentionally manual, and the supervisor stops on it until an operator records completion.

## Mission 008 — End-to-End Pipeline: complete

- Added temporary-SQLite integration coverage across passive recon, offline brief, hypothesis generation, manual review, and explicit verification approval. Network, LLM, and verifier boundaries are mocked; no repository evidence databases are opened.
- Additional cases cover failure and explicit retry, stuck-task recovery, budget exhaustion, and a verification task remaining pending without a supplied plan.
- Tests: pipeline/supervisor/planner/task-runner focus — 42 passed; evidence/verdict/verification/pipeline focus — 95 passed.
- Files: `tests/test_supervised_pipeline.py`, `tests/test_supervised_cycle.py`.
- Limitations: live network, model, and lab verification remain deliberately untested here.

## Mission 009 — Hardening and Completion: complete

- Hardening fix: verification evidence now strips URL query strings and fragments before persistence, preventing common query-token disclosure while retaining host/path context. Sensitive response headers are already filtered by the probe layer; request headers remain transient.
- Added regression coverage for query/fragment redaction and updated architecture/roadmap/handoff behavior descriptions.
- Tests: focused evidence/verdict/verification/pipeline set — 77 passed after the final plan-binding change. Broader safe regression suite — 621 passed, 12 repository-evidence database-copy cases deselected to avoid reading checked-in evidence databases.
- Files: `verification/evidence.py`, `verification/run_hypothesis_verification.py`, `tests/test_evidence.py`, `tests/test_run_hypothesis_verification.py`, `tests/test_verification_plan_input.py`, `ARCHITECTURE.md`, `NEXT_STEPS.md`, `CLINE_HANDOFF.md`.

Next: human review of the uncommitted Missions 004–009 diff; no commit or push was made.

## Mission 010 — Operator Acceptance and CLI Testability: complete

- Added a shared `--database PATH` option and safe existing-file path handling. Read/write commands require an already-ready database and open SQLite with `mode=rw`; they do not create or migrate schemas. The status board opens its selected existing database with SQLite `mode=ro`. Omitting the option retains each command's previous `lab_evidence_v3.db` default.
- Configurable commands: `scripts/run_supervised_investigation.py`, `scripts/run_investigation_step.py`, `scripts/collect_inventory.py`, `scripts/recover_investigation.py`, and `scripts/investigation_status.py`.
- Added actual CLI entry-point integration tests using isolated temporary databases. Coverage includes repeatable byte-stable dry runs, supervised and one-step execution, scope and budget gates, verification plan/approval/lab gates including mismatched hypothesis binding, transient credentials, task failure and retry recovery, inventory collection routing, read-only status output, and refusal of missing/unready database paths. Recon and verification dispatch are mocked.
- Tests: CLI/status focus — 39 passed. Broader suite — 634 passed, 13 deselected because those migration/integrity tests copy checked-in evidence databases; those cases were not run under the production-database restriction. `git diff --check` and Python compilation passed.
- No checked-in production evidence database was opened, initialized, migrated, modified, or used as a test fixture. No external verification or reconnaissance was performed.
- Limitations: this adds database selection to the investigation workflow and status commands only; separate lab-only and finding-report commands retain their purpose-specific database handling. Valid verification execution was tested with a mocked verifier, not a real target.

Next: Mission 011 — independent audit of the combined Missions 004–010 implementation.

## Mission 011 — Independent Technical Audit: complete

- Audited planning, dependency/budget checks, scope enforcement, task dispatch and transitions, transient verification approval, evidence handling, retry/recovery, and operator database selection. Most boundaries are consistently enforced: dispatch requires caller authorization for network task kinds, verification requires a hypothesis-bound plan plus explicit approval and lab mode, dispatch writes are savepoint-protected, and only a fresh CLI invocation supplies authorization to a retry.
- Confirmed defect (high, sensitive data): `scripts/collect_inventory.py::_base_hostname` accepted URL userinfo and `run_collect_inventory` persisted the full URL in `Task.title` and `Task.params`. A temporary-DB CLI reproduction rejected the URL before probing but confirmed the dummy credential remained in both stored fields.
- Confirmed defect (medium, scope/data integrity): the inventory CLI did not reject an out-of-scope base before creating its asset/task. A temporary-DB CLI reproduction returned exit 0, persisted the out-of-scope asset and inventory task, and reported successful collection of zero observations. No network request was made because all seed URLs were rejected by policy.
- Confirmed defect (medium, operator reporting): `scripts/run_investigation_step.py::main` caught task failures/refusals, printed them, then returned exit 0. Shell/operator automation could mistake failed or blocked work for success.
- No confirmed defect found in stored endpoint ownership checks, verification plan binding and approval gates, verification credential persistence, planner budgets, or retry authorization. A later Mission 013 two-session reproduction confirmed that duplicate planner reads could create duplicate task chains; SQLite is now serialized before planner reads and a database unique key protects generated tasks. PostgreSQL remains experimental and its concurrency behavior is not treated as a supported guarantee.
- Tests: temporary-database reproductions for both inventory defects; no source changes were made for the audit itself.
- Next: Mission 012 — reject unsafe/out-of-scope inventory inputs before persistence, and return a failure exit status when one-step execution encounters a task failure or refusal.

## Mission 012 — Critical Defect Remediation: complete

- Inventory CLI and library validation now reject URL userinfo, query strings, fragments, malformed ports, and out-of-scope base URLs before creating assets or tasks. Error text does not echo the submitted URL. Scope rejection is enforced both at the operator boundary and in `run_collect_inventory()`.
- `scripts/run_investigation_step.py` now exits nonzero after a task dispatch failure or refusal while retaining the task's existing failure audit behavior and leaving pre-dispatch refusals pending.
- Added temporary-database CLI regressions for sensitive/malformed URLs, out-of-scope asset/task creation, dispatch failure exit status, and verification refusal exit status.
- Tests: `tests/test_operator_cli.py`, `tests/test_collect_inventory.py`, `tests/test_endpoint_inventory_collector.py`, `tests/test_task_runner.py` — 56 passed.
- No production evidence database was accessed; no network operation was made by these tests.
- Next: Mission 013 — assess database transaction, concurrent task/plan creation, rollback and session lifecycle reliability; implement only reproducible gaps.

## Mission 013 — Database Reliability: complete

- Reproduced concurrent duplicate planning with two independent SQLite sessions. Added a transaction-scoped `BEGIN IMMEDIATE` planner lock before reads and stable unique `Task.dedupe_key` values; an additive schema migration (v4) creates the nullable column and unique index. On a key conflict, the planner reuses the committed task within a savepoint without taking ownership of the caller's transaction.
- Fixed partial inventory setup rollback: budget exhaustion before task creation no longer leaves a speculative asset, while a failed dispatch task and its audit record remain available for diagnosis.
- Added deterministic two-session concurrency, v3-to-v4 migration, and inventory budget rollback regression coverage. Existing task/event writes remain caller-transaction scoped.
- Tests: planner, task lifecycle, task runner, supervisor, fresh/read-only/idempotent migration, and v4 upgrade focus — 93 passed.
- Files: `data/models.py`, `data/migrations.py`, `verification/investigation_tasks.py`, `orchestration/inventory_planner.py`, `scripts/collect_inventory.py`, `tests/test_inventory_planner.py`, `tests/test_db_migrations.py`, `tests/test_operator_cli.py`, `ARCHITECTURE.md`, `MISSION_PROGRESS.md`.
- Limitations: SQLite planner calls serialize database-wide writes for the duration of the caller's transaction. PostgreSQL concurrency remains experimental and untested. General task-budget enforcement is still an application-level count check, not a database quota constraint.
- Next: Mission 014 — audit and test scope freshness, endpoint ownership, lab-only verification, approvals, budgets, and sensitive-data boundaries end to end.

## Mission 014 — Security and Policy Enforcement: complete

- Network dispatch now intersects the operator-supplied authorizer with the program's freshly loaded current scope and refuses inventory, recon, or verification work before starting a task when current authorization denies it. Verification URLs must match the hostname of the hypothesis asset, preventing in-scope cross-asset evidence from being attached to the wrong hypothesis.
- Crash-recovery reasons now have a 500-character bound and reject common credential patterns, URL userinfo, control characters, and blank input with generic errors before task state or audit history changes.
- Regression coverage includes narrowed scope after authorizer construction, unauthorized recon/inventory refusals, cross-host verification rejection before pinning, transient verification credentials, and secret-shaped recovery reasons.
- Tests: task runner, verification, verification-plan input, operator CLI, and recovery focus — 101 passed.
- Files: `orchestration/task_runner.py`, `verification/run_hypothesis_verification.py`, `verification/task_recovery.py`, `tests/test_task_runner.py`, `tests/test_run_hypothesis_verification.py`, `tests/test_task_recovery.py`, `tests/test_operator_cli.py`, `ARCHITECTURE.md`, `MISSION_PROGRESS.md`.
- Limitations: pattern checks cannot guarantee that all free-form operator text is secret-free. PostgreSQL remains experimental; this mission does not enable public-target verification.
- Next: Mission 015 — improve deterministic endpoint prioritization, evidence-gap reporting, and explanations without inventing findings or making external calls.

## Mission 015 — Investigation Intelligence: complete

- Inventory planning now selects one review task per canonical endpoint URL and reports redundant observation ids. Review tasks are ordered deterministically by stored HTTP status class and carry an operator-visible explanation that status is context, not proof or severity.
- Researcher observation cards explicitly list missing provenance, response-size, and body-digest metadata. Existing support links remain attached to their originating observations; the brief does not elevate those links into proof.
- Tests: planner, research workflow, supervised cycle, and end-to-end pipeline focus — 43 passed.
- Files: `orchestration/inventory_planner.py`, `intelligence/research_workflow.py`, `scripts/run_supervised_investigation.py`, `tests/test_inventory_planner.py`, `tests/test_research_workflow.py`, `ARCHITECTURE.md`, `MISSION_PROGRESS.md`.
- Limitations: ordering is a transparent response-status heuristic, not vulnerability severity or confidence; query strings are used only in-memory as part of endpoint identity. Candidate generation remains human-reviewed and unverified.
- Next: Mission 016 — exercise and improve interrupted-task recovery, retries, duplicate execution prevention, and audit-event consistency.

## Mission 016 — Recovery and Idempotency: complete

- Task starts and terminal transitions now use conditional database updates in savepoints; each status change and its corresponding append-only event commit or roll back together. Two sessions holding stale pending state cannot both start the same task.
- Retry tasks use a stable unique dedupe key. Retry creation and the original task's `retry_created` event are savepoint-atomic; failed audit insertion leaves no orphan retry. Crash-recovery reasons remain bounded and reject common credential-shaped content.
- The supervised, one-step, and inventory operator CLIs checkpoint `running` plus `started`/`dispatched` events before network-facing work. A simulated process exit leaves a stuck task visible to recovery. Retries remain pending and need new invocation authorization and approvals.
- Tests: recovery, task lifecycle, task runner, supervised cycle, collector/session helper, operator CLI, and supervised pipeline focus — 149 passed; two isolated inventory CLI checkpoint cases — 2 passed.
- Files: `verification/investigation_tasks.py`, `verification/task_recovery.py`, `orchestration/task_runner.py`, `orchestration/supervised_cycle.py`, `scripts/run_investigation_step.py`, `scripts/run_supervised_investigation.py`, `scripts/collect_inventory.py`, `tests/test_investigation_tasks.py`, `tests/test_task_recovery.py`, `tests/test_task_runner.py`, `tests/test_collect_inventory.py`, `tests/test_session_helpers.py`, `tests/test_operator_cli.py`, `ARCHITECTURE.md`, `MISSION_PROGRESS.md`.
- Limitations: checkpoint mode commits all pending changes in the operator's session, including planned tasks; library calls retain caller-owned transaction semantics by default. Long-running active tasks still require human judgment before marking failed or retrying, because the system cannot know whether an external request completed before a process died.
- Next: Mission 017 — audit evidence provenance, task/hypothesis links, validation, duplicate handling, redaction, and retention consistency.

## Mission 017 — Evidence Integrity: complete

- Validated inventory and verification probe fields before persistence: status range/type, finite non-negative elapsed time, non-negative content length, SHA-256 shape, and header mapping. Comparison summary flags and header differences are now derived from the sanitized probe records rather than trusting caller-supplied `DiffResult` summaries.
- Authorization provenance snapshots are bounded to known fields, must identify the matching asset and current program scopes, require an affirmative caller-authorization assertion, and reject secret-shaped/malformed scope values. Endpoint inventory collection now rejects a base host that does not match the stored asset before authorization callbacks or transport invocation.
- Newly inserted ORM observations must have a non-empty bounded type and finite JSON-object data. Retained evidence, provenance, support links, verdicts, findings, task events, and promotion audit rows reject ORM updates. SQLite schema migration v5 adds and readiness validates matching `BEFORE UPDATE` immutability triggers; migration failure rolls back the triggers and history row together.
- Migration v6 preserves its original task-observation relationship purpose: it creates the immutable `task_observations` table, its SQLite update/delete triggers, and a database trigger rejecting cross-investigation task links. It does not require fingerprint tables as part of the historical v6 contract. Migration v7 introduces `observation_fingerprints` storage, its update/delete triggers, and safe idempotent backfill for existing observations. Schema-contract validation and runtime readiness reject missing or altered protections; each migration's DDL and history row remain transaction-atomic. ORM retained-record guards include both tables.
- Task dispatch records input relationships for research briefs and hypothesis generation, output relationships for inventory, recon, and verification, and planner-created manual review tasks link the specific inventory observation as input. The link writer validates task/observation investigation ownership, with a SQLite insert trigger enforcing the same rule for direct SQL.
- New observations receive a canonical SHA-256 fingerprint and a `duplicate_of_observation_id` pointer when their canonical payload, type, asset, and hypothesis exactly match an earlier row. Hash matches are verified against canonical bytes; duplicate rows remain separately stored and auditable. Migration v7 fingerprints existing observations without fabricating task links, and a v6 database that already contains fingerprint structures (from the earlier expanded definition) is upgraded idempotently without losing data.
- Historical tasks/observations without provable associations remain unknown; no task links are inferred from old titles or summaries. Direct library/CLI evidence creation outside a task also remains unlinked unless task context exists.
- Synthetic migration safety: replaced legacy-copy migration tests with temporary synthetic schemas for source versions v0, v4, and v5. All three upgrade tests preserve existing rows and reach the current schema. Repository tests contain no references to checked-in `lab_evidence*.db` files.
- Latest results: migration plus database-integrity suites — **88 passed** (now 90 with the added historical-v6 and interim-v6 cases); the full `tests/` regression suite — **707 passed, 0 failed**. `compileall` and `git diff --check` passed.
- Test-access history: an earlier run inadvertently executed legacy-copy tests that read checked-in evidence databases as copy sources; that incident is retained here for transparency. In this continuation, no checked-in evidence database was opened, copied, migrated, or inspected.
- Release-blocking compatibility question resolved: the task-observation v6 contract is now stable and the fingerprint storage/backfill/protections moved into migration v7. A database that recorded the historical task-links-only v6 upgrades through v7 while preserving its task links and observations; a database that already contains fingerprint structures at v6 is handled idempotently. Synthetic tests cover v0/v4/v5 → latest and historical v6 → v7. No checked-in evidence database was inspected to answer this.
- Remaining security and evidence limitations: task provenance cannot be reconstructed for historical or direct non-task API writes; response bodies are not retained, so their digests cannot be recomputed; a database owner with SQLite DDL privileges can alter/drop triggers, which readiness detects on startup (the finding-report consumption gate re-verifies verdict digests as defense in depth). PostgreSQL remains out of scope.
- Missions 018–020 have not been started because their objectives were not present in the supplied instructions.

## Mission 018 — Operator Experience: complete

- Scope refusals now explain the offending host plus the investigation's authorized and excluded scope, so an operator can correct the command instead of guessing (`scripts/collect_inventory.py`).
- A supervised-cycle task failure now prints recovery guidance pointing at `scripts/recover_investigation.py <investigation> --retry <task_id>` after the stop-on-first-failure message (`scripts/run_supervised_investigation.py`).
- The read-only status board now flags budget exhaustion explicitly when either the task or LLM-call budget has no remaining headroom (`scripts/investigation_status.py`).
- Preserved all existing CLI flags and exit-code behavior; dry runs remain non-mutating and secrets stay out of operator output.
- Tests: `tests/test_operator_cli.py` — 26 passed (three new regression cases: recovery guidance, scope explanation, budget-exhaustion flag); status-board/collect-inventory/supervised-cycle focus — 43 passed.

## Mission 019 — Resilience and End-to-End Testing: complete

- Audited the 17-point supervised-workflow checklist against existing coverage: programme/scope initialization, inventory collection, inventory planning, passive recon, research briefs, hypothesis generation, human review, verification plan creation, approval/lab restrictions, evidence collection and provenance, task failures, process interruption, recovery and retry, duplicate execution, budget exhaustion, and CLI reporting/exit codes are all exercised by `tests/test_supervised_pipeline.py`, `tests/test_supervised_cycle.py`, `tests/test_operator_cli.py`, `tests/test_task_recovery.py`, `tests/test_investigation_tasks.py`, `tests/test_task_runner.py`, `tests/test_task_events.py`, `tests/test_inventory_planner.py`, `tests/test_collect_inventory.py`, `tests/test_evidence.py`, and `tests/test_run_hypothesis_verification.py` on isolated temporary SQLite databases with network/LLM/verifier boundaries mocked.
- Added the missing database-failure case: a tampered database with a dropped retention trigger is refused by the operator entry point before any dispatch, leaves the file byte-for-byte unchanged, and leaves the task pending with only its `created` event (`tests/test_operator_cli.py::test_tampered_database_is_refused_before_any_dispatch`).
- Verified the key invariants hold across the workflow: interrupted tasks cannot silently become successful (stuck tasks block and remain `running`; failed dispatches mark `failed`), retries never create duplicate task chains (dedupe key + planner), failed operations store no partial evidence, and audit/provenance rows stay consistent.
- Tests: supervised-workflow integration focus (12 suites) — **211 passed, 0 failed**.

## Mission 020 — Release Readiness: complete

- Release review verified against the code and the full suite: fresh databases initialize to schema version 7; synthetic v0/v4/v5 and historical v6 → v7 databases upgrade safely and idempotently; failed migrations roll back their DDL and history; readiness and integrity checks detect missing or altered retention/immutability/ownership/fingerprint triggers; operator entry points refuse tampered or non-ready databases without writing.
- Updated stale schema documentation: `ARCHITECTURE.md` now lists migrations 1–7 (previously stopped at version 5), and `NEXT_STEPS.md` records Missions 017–020 as complete.
- Confirmed all documented features exist and failure/refusal states are observable through nonzero CLI exit codes and explicit messages; security boundaries (scope, approval, lab-only verification, retained-record immutability) cannot be bypassed through supported interfaces.
- Final regression: full `tests/` suite — **711 passed, 0 failed** (707 baseline + 4 new Mission 018/019 cases); migration plus database-integrity suites — **90 passed**; `compileall` and `git diff --check` passed.

### Release verdict: CONDITIONALLY APPROVED

- Evidence: 711 passing tests, transactional additive migrations with rollback, readiness detection, human-gated lab-only verification, and read-only operator reporting support a controlled V1.0 release.
- Operational restrictions before controlled real-world operation: (1) database migration requires a maintenance window — stop every writer and follow the verified-backup procedure in `ARCHITECTURE.md` (the `--confirm-writers-stopped` flag is a human acknowledgment, not process detection); (2) network verification remains lab-only and requires a transient plan plus explicit approval, never autonomous promotion; (3) no live reconnaissance or verification has been run against a real program-authorized domain — a human must review `gateway/dns_pin.py` and configure only program-authorized targets first; (4) the DeepSeek key must be supplied via environment/secret manager and never committed.
- Remaining limitations: response bodies are not retained so body hashes cannot be recomputed; PostgreSQL immutability is out of scope; historical/direct non-task evidence has no reconstructable task provenance; a database owner with SQLite DDL privileges could alter protections, which readiness detects on startup.

## DNS Pinning Hardening (post-Mission-020 remediation): complete

- Replaced the insufficient `address.is_global` gate with an explicit `is_public_unicast()` predicate in `gateway/dns_pin.py`. It rejects IPv4 multicast (224.0.0.0/4), IPv6 multicast (ff00::/8), ORCHIDv2 (2001:20::/28), unspecified, reserved, private, loopback, link-local, and IPv4-mapped IPv6 addresses that embed a prohibited IPv4 address, and continues to accept ordinary public IPv4/IPv6 unicast. Every DNS answer is still validated; a single prohibited answer rejects the whole resolution.
- Lab mode is unchanged and remains a separate, explicitly authorized private-IP path (`gateway/lab_mode.py`); the public gate was not weakened and scope checks remain deny-by-default.
- Added regression tests: `224.0.0.1`, `239.255.255.250`, `ff02::1`, `2001:20::1`; mixed public+multicast and public+prohibited-IPv6 answers; ordinary public IPv4/IPv6 acceptance; resolver raising `OSError` and `socket.gaierror`; the HTTP proxy-rejection branch; and confirmation that a hostile `HTTPS_PROXY` environment variable cannot bypass the pinned transport.
- Verification: DNS pinning/HTTP probe/scope/lab-mode focus — 93 passed; network-integration focus (verification, inventory, diff, task runner, e2e, supervised pipeline, lab verification) — 85 passed; full `tests/` suite — **740 passed, 0 failed**. `compileall` and `git diff --check` passed.
