# Architecture

## V1 Scope

V1 provides program configuration, scope enforcement, safe DNS resolution, passive DNS discovery, relational storage, and an explicit single-request HTTP probe for controlled verification. It does not perform autonomous investigation or vulnerability checks. The current interface is a set of Python modules; there is no CLI or service entry point yet.

## Database schema migrations

Database engine construction, fresh initialization, readiness validation,
integrity checking, and migration are separate operations in `data.db`.
Ordinary application startup calls `open_ready_database()`: it builds an
engine, validates the existing schema without writing, and refuses startup
with an actionable message if explicit migration is needed. It never migrates.

`initialize_fresh_database()` is only for a genuinely empty database. It creates
the current schema and migration history transactionally, and refuses any
database containing existing tables, views, or other SQLite objects. The
deprecated `init_db()` wrapper is fresh-only; it no longer migrates.

An operator explicitly upgrades an existing SQLite database with:

```sh
python -m scripts.migrate_database --database /path/to/evidence.db \
  --confirm-writers-stopped
```

The operator must stop every process that can write to the database and keep
them stopped through migration and readiness validation. The required flag is
a human acknowledgment; it does not detect or stop other processes. The command
performs read-only, version-aware preflight checks, including schema constraints
and existing orphaned rows, and refuses unsupported or incomplete schemas.
Before migration it uses SQLite's online backup API (safe
for WAL databases), writes a new backup without overwriting existing files,
opens and integrity-checks that backup, and records its SHA-256 in a `.sha256`
sidecar. It then applies the numbered migrations and validates the resulting
schema and database integrity. A failed migration is not automatically
restored: keep application writers stopped, retain the failed database and backup,
inspect the reported failure, and verify the backup checksum and contents
before an operator manually chooses a recovery action. Never overwrite the
failed database automatically.

The current schema version is 7:

1. `investigation_budgets` adds nullable `max_tasks` and `max_llm_calls` columns
   to `investigations` when they are absent.
2. `task_verification_and_v81_tables` creates missing task, verification, audit,
   hypothesis-support, and observation-provenance tables. Existing tables and
   their records are left in place.
3. `sqlite_historical_record_retention` adds SQLite `BEFORE DELETE` triggers to
   retained evidence and audit tables.
4. `concurrent_task_deduplication` adds a nullable, unique `tasks.dedupe_key`
   index. Inventory-planned tasks use stable keys so concurrent planning cannot
   persist duplicate task chains; unrelated operator-created tasks may leave
   the key NULL.
5. `sqlite_historical_record_immutability` adds SQLite `BEFORE UPDATE` triggers
   for retained evidence and audit tables. Existing rows are preserved; updates
   are refused rather than rewritten.
6. `task_observation_links` creates the immutable `task_observations`
   relationship table plus its retention, immutability, and cross-investigation
   ownership triggers. This is the historical task-observation contract only;
   it does not require fingerprint storage.
7. `observation_fingerprints` creates fingerprint storage and its retention and
   immutability triggers, and idempotently backfills fingerprints for existing
   observations without fabricating task links. A version-6 database that
   already contains fingerprint structures upgrades through this step without
   losing data.

Migration history and each migration's DDL are committed together. A failed
migration rolls back that step and can be retried; previously completed steps
remain recorded. Re-running initialization is idempotent. Unsupported or
incomplete unversioned schemas fail explicitly rather than being reset or
silently treated as current.

### Referential integrity and evidence retention

SQLite foreign-key enforcement is enabled on each DBAPI connection created by
`data.db.create_database_engine()` and by the read-only report/status tools,
before a transaction begins. Fresh initialization and schema readiness run
`check_database_integrity()` and fail
if declared constraints are missing, have unsafe delete actions, enforcement
is off, or existing foreign-key violations are detected; it does not repair or
delete orphaned records.

Parent relationships use restrictive foreign keys and do not cascade deletes.
Deleting a program, investigation, asset, hypothesis, observation, task, or
finding is rejected while referenced records remain, whether the delete is
issued through the ORM or SQL. Existing SQLite databases use non-deferrable
`NO ACTION` foreign keys, which also reject those deletes; fresh and newly
created tables declare `RESTRICT`.

Standalone `Observation`, `ObservationProvenance`,
`HypothesisSupportingObservation`, `Verdict`, `Finding`, `TaskEvent`, and
`PromotionAudit` records cannot be permanently deleted through normal ORM
operations (including bulk deletes), and cannot be updated through normal ORM
operations or direct SQL. SQLAlchemy session guards reject ORM updates and
deletions; SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers using
`RAISE(ABORT, ...)` provide database-level enforcement. The integrity checker
verifies each required trigger's table, timing, operation, and effective
definition; it reports missing or altered triggers without recreating them.
Evidence writers validate probe metadata before persistence, derive comparison
flags from the validated probe records, and accept only bounded authorization
snapshot fields so arbitrary caller data cannot be copied into provenance.
New ORM observations must carry a non-empty type and finite JSON-object data;
the evidence helper rejects malformed probe values and requires supplied
authorization snapshots to match the asset and current program scope. URL query
values and fragments, sensitive response headers, and secret-shaped response
header values are excluded from persisted probe evidence. This does not claim
that arbitrary target-controlled DNS text or legacy rows are credential-free.

Investigation lifecycle transitions remain the supported way to close work;
archival or status transitions are preferred to deleting evidence. SQLite
retention triggers are implemented in schema migration version 3 and
immutability triggers in version 5.

SQLite migrations acquire an immediate write lock and use transactional DDL.
PostgreSQL uses transaction-scoped advisory locking and SQLAlchemy-generated
table DDL, but is experimental and has not been validated against a PostgreSQL
server. SQLite is the supported migration and backup target. Future schema
changes must add a new migration version rather than rewriting an already
released migration.

The referential-integrity behavior has been tested with SQLite only. SQLAlchemy
ORM update/delete guards apply when writes pass through the configured ORM
session, but PostgreSQL direct-SQL retention and immutability triggers are not
implemented. PostgreSQL migration locking and database-level delete/update
behavior remain unverified against a PostgreSQL server.

## Mission 003: Offline researcher workflow

`intelligence.research_workflow.build_researcher_brief(asset_id, session)`
reviews only observations already stored for one asset. It performs no DNS or
HTTP requests, does not call an LLM, and does not execute verification tasks.
It returns bounded observation cards with stored provenance metadata and
creates/reuses only unverified review hypotheses for valid
`endpoint_inventory` records. Each candidate is linked to its supporting
observation through `HypothesisSupportingObservation`.

The generated access-policy review candidate explicitly treats the stored HTTP
status and response metadata as context, not proof of a weakness. Confidence is
unassessed and impact is undetermined. The brief recommends comparing the
observation with documented program policy; any active verification requires a
researcher to confirm scope and approve a separate verification plan. The
workflow flushes but never commits, so the caller owns persistence. It omits
target response headers, body content, raw DNS values, and unrecognized
observation data from the brief.

This is deliberately an offline-only researcher aid, not a reconnaissance
orchestration engine. Live recon, automated vulnerability hypothesis generation
and external model calls are outside this implementation scope.

### Mission 003B: Researcher intelligence dashboard

The existing read-only operator status board can render a researcher view with
`scripts/investigation_status.py --investigation <id> --researcher-dashboard`.
It presents stored asset, observation, hypothesis, and finding counts; groups
bounded observation summaries by asset ID (hostname is display metadata only);
includes available provenance; and
shows hypothesis status, support-observation IDs, missing or unavailable
support, and next-step recommendations. Confidence and impact are displayed as
unrecorded when the schema has no such fields. The existing deterministic
unverified-hypothesis ordering is shown only as a review order, not a severity
or confidence score.

Stored observations are labeled as records rather than vulnerability verdicts.
Hypotheses remain clearly identified as inferences unless a human-approved
`Finding` row exists; even then the dashboard does not independently re-verify
the finding. Support links record research context and are never treated as
proof. Recommendations are evidence-linked review suggestions, not verification
commands; active verification still requires confirmed authorization and
explicit researcher approval.

Dashboard generation and rendering only read existing database rows. Library
queries run with SQLAlchemy autoflush disabled and use column projections, so
caller-owned pending inserts, edits, and deletes are neither flushed nor
overwritten. The dashboard does not commit, flush, roll back, or change pending
session state. It does not invoke `build_researcher_brief()`, create hypotheses
or support links, make network requests, call an LLM, or promote findings. The
CLI opens the database with SQLite read-only mode.

The dashboard checks required columns before querying every relevant table.
Absent tables and incomplete tables are reported as unavailable; their
corresponding grouped collections are `None` and counts are unavailable rather
than zero. Zero and empty collections are reported only when the available
schema was queried and no matching records were found. Optional
provenance metadata and budget columns are reported as unavailable or partial
when not present; the dashboard never migrates or creates tables.

## V2 Scope

V2 adds investigation intelligence on top of V1: it summarizes the observations already stored for one asset, asks a model for candidate hypotheses through the first live `intelligence.llm_client` caller, and ranks those candidates with a deterministic rule. It produces **unverified candidates only**. No V2 module probes the network, runs a tool, changes a hypothesis status, or commits the caller's transaction; a human still has to invoke a verification flow before anything becomes evidence.

## V3 Scope

V3 adds *controlled verification* on top of V2: a deterministic verdict checker, a verdict-integrity binding, a gated runner for a human-authored test plan, one human-only promotion gate that turns supported evidence into a `Finding`, and a pure Markdown report renderer. It produces **machine-checked verdicts, not findings by default**. The checker is a pure function (no session, network, clock, or model), the runner uses only the guarded lab transport and never commits or edits a status, and the promotion gate is the single module in the project that writes `Hypothesis.status` or creates a `Finding` row. Nothing in V3 runs on a schedule, and no report is submitted anywhere.

Every stored verdict carries an integrity digest binding its semantic content to the evidence row it judged, the hypothesis, and the recorded target URLs, plus a canonical digest of the stored evidence. `verification.verdict_integrity.verify_verdict()` recomputes both the digest and the judgement, and **every consumer of a verdict verifies it first**: `promote_to_finding()` refuses to promote on any verdict that fails the check, and the report loader refuses to load a context containing one. A hand-written row, a row rebound to another observation, hypothesis, or target, and a row whose evidence or wording was edited are rejected rather than trusted.

### Verification lifecycle invariant

**verified ≠ approved ≠ reported — three separate states with three separate writers.** Evidence passing the checker, a human approving it, and a report being rendered are distinct steps, not one pipeline:

1. *Verified* — `verification.verdict_checker.check_verdict()` judges stored bytes and `verification.evidence.store_verdict()` writes the `Verdict` row. The writer of this state writes verdicts only: never a status, never a `Finding`, never a report.
2. *Approved* — a named human calls `verification.finding_promotion.promote_to_finding()`. This is the **only** writer of `Hypothesis.status` and the only creator of `Finding` rows, and it requires a valid integrity digest on every verdict it reads.
3. *Reported* — `verification.finding_report.render_finding_report()` renders a promoted finding from stored rows. `collect_finding_context()` verifies integrity again; the renderer is pure and writes nothing.

No state implies the next: a `supported` verdict is not a finding, a `Finding` is not a report, and nothing in V3 schedules, submits, or auto-promotes.

### Inventory observations are context, never verdict evidence

`verification.endpoint_inventory_collector.collect_seed_inventory()` can store an `endpoint_inventory` observation: one authorized response from the fixed seed list that `verification.endpoint_inventory` builds. It reuses the allowlisted probe mapping a comparison records, so it *is* digest-bindable — and that is exactly why the boundary is stated rather than assumed: being digest-bindable is not the same as being judgement evidence. Three independent gates keep it out of verdicts:

* `verification.verdict_integrity.verify_verdict()` accepts the `diff_check` observation type only and returns `evidence_type_mismatch` for anything else.
* `verification.evidence.store_verdict()` refuses to write a verdict row that fails that same check, so the refusal happens before anything is stored.
* `verification.finding_promotion.promote_to_finding()` refuses a verdict whose evidence is not a `diff_check`, so even a hand-written supported row over an inventory observation cannot produce a `Finding`.

Only `CROSS_ACCOUNT_SAME_BYTES` verdicts are re-derivable at all (`_RE_DERIVABLE_CLAIM_TYPES`), and `verdict_integrity.target_urls()` reads `probe_a`/`probe_b`, which an inventory row does not carry, so one binds no target a verdict could cite. Inventory rows are therefore asset-level context: they feed `intelligence.observation_summary`, which splits an `endpoint_inventory` row by field — its system-derived scalars (the requested `url`, `status_code`, `content_length`, `body_sha256`, `response_time_ms`) enter the trusted text through the fixed field vocabulary, while the target-chosen response `headers` (names and values alike) stay `UntrustedText`, exactly like any unrecognized field. Through that summary they reach hypothesis generation. Turning an inventory probe into evidence would need a new claim type and a new digest shape, which is a deliberate schema change rather than something a collector can cause.

## V4 Scope

V4 adds a persistent investigation lifecycle on top of V3: `verification.investigation_lifecycle.start_investigation(program_id, session)` opens one `Investigation` row (`status='running'`, `started_at` set) and `close_investigation(investigation_id, session, *, final_status)` closes it with a final `status` (`completed` or `cancelled`) and `ended_at`. It is the smallest V4 slice: two session functions only, no scheduler, no CLI wiring, and no schema change, because `Investigation` already carried `program_id`, `status`, `started_at`, and `ended_at`. Both functions flush and never commit, and neither imports the gateway, calls a model, makes a request, or touches a `Hypothesis`, `Finding`, `Verdict`, or `Observation`. `Investigation.status` is the lifecycle field, written only by this module, and it is distinct from `Hypothesis.status`, which remains written only by `verification.finding_promotion.promote_to_finding()`.

### Investigation tasks (human-triggered only)

The V4 orchestration foundation makes an investigation a container for work. `verification.investigation_tasks` records operator-tracked `Task` rows inside a running investigation: `create_task(investigation_id, session, *, kind, title)` adds a `pending` task, `start_task(task_id, session)` moves it to `running`, `complete_task(task_id, session, *, final_status, result_summary=None)` ends it as `completed`, `failed`, or `cancelled`, and `list_tasks(investigation_id, session)` reads them in creation order. A task is a **record, not a job**: there is no scheduler or autonomous worker, and each transition is initiated by an operator command. `create_task` requires an existing running investigation, a kind from the fixed allowlist, and exactly that kind's `TASK_PARAMS`; a `verification` task must name a positive `hypothesis_id` already in the investigation. `completed`/`failed` require a running task, `cancelled` also accepts a pending one, and terminal tasks never change. Task lifecycle functions flush and never commit, import nothing from the gateway, and never touch hypotheses, findings, verdicts, or observations. Status transitions use conditional database updates inside savepoints, and the transition plus its append-only task event either succeeds together or rolls back together.

Two hard budgets bound an investigation's work, carried as nullable `Investigation` columns (`max_tasks`, `max_llm_calls`) whose `NULL` falls back to the module defaults (`MAX_TASKS_PER_INVESTIGATION = 50`, `MAX_LLM_CALLS_PER_INVESTIGATION = 10`). `create_task` — the only writer of tasks — enforces both and raises `BudgetExhausted` (a `ValueError`) instead of adding a task beyond them; the LLM budget counts `hypothesis_generation` tasks, the project's only production path to the model, so the cap is hit before any model call. `plan_next_tasks` applies the task budget defensively as well.

Close policy: **strict block.** `close_investigation()` raises `OpenTasksError` (a `ValueError`) with nothing changed while any task of that investigation is `pending` or `running`; it never cancels a task on the operator's behalf. So a closed investigation never has an open task, and `create_task` cannot add one to it.

`Task` columns (the minimal set):

- `id` — primary key, the handle every task function takes.
- `investigation_id` — the owning investigation; the foreign key that makes an investigation a container and lets `close_investigation` find open work.
- `kind` — one of the six allowlisted kinds, so a task names a known step of the existing lifecycle rather than free-form work.
- `status` — `pending`/`running`/`completed`/`cancelled`/`failed`, the transition state the functions guard and the close check reads.
- `title` — the operator's human-readable description of the work; required and non-blank.
- `created_at` — when the operator recorded the task; also a stable audit timestamp independent of whether it ever started.
- `started_at` — when the operator started it; `NULL` for a task cancelled before it started, which distinguishes "dropped" from "attempted".
- `ended_at` — when it reached a terminal status, mirroring `Investigation.ended_at`.
- `result_summary` — optional operator note on the outcome (up to 2000 characters); it is a note, never evidence, and nothing reads it as a verdict.
- `dedupe_key` — nullable unique key for planner and retry idempotency; ordinary tasks may leave it NULL.

The schema is additive: migration version 2 creates task and verification tables, version 4 adds the nullable task deduplication key/index, version 6 adds the `task_observations` relationship table, and version 7 adds fingerprint storage with backfill. `init_db()` is deprecated and fresh-database-only; it refuses an existing database and does not migrate it.

### Operator runs own an investigation and its tasks

An operator script can own the container and its task records. `orchestration.session_helpers.ensure_running_investigation()` returns a running `Investigation`; `run_under_investigation()` creates and dispatches an existing task kind or calls an operator work function. Library helpers leave commit ownership to the caller. The operator execution CLIs explicitly checkpoint a task's `running` state and `started`/`dispatched` events before network-facing work, so an interrupted process leaves a recoverable stuck task. `scripts/collect_inventory.py` uses the same checkpoint mode for CLI execution; direct library calls remain caller-transaction scoped.

Those tasks are the same records recovery operates on: `verification.task_recovery.find_stuck_tasks()` lists an investigation's overrun `running` tasks, and `scripts/recover_investigation.py --mark-failed` / `--retry` repair them through the same task layer. Status updates are conditional database updates, preventing two sessions with stale `pending` state from both starting the same task. Each transition and its audit event use one savepoint. Retry creation uses the unique `retry:v1:<original-task-id>` key and records its link in the same savepoint; a failed retry-audit write leaves no retry task. Recovery stays human-initiated — no scheduler, daemon, or auto-retry exists, and a retry remains pending until a separate invocation supplies fresh scope authorization and any required approval.

## V6 Scope (first slice)

The supervised cycle is a **human-triggered bounded loop**, not an autonomous service: an explicit invocation proposes ready tasks and, only when told to, runs them once each. `orchestration.supervised_cycle.run_supervised_cycle(investigation_id, session, *, execute, threshold_seconds=3600.0, authorize=None, allow_private_network=False, verification_plan=None, approve_verification=False)` is the library entry point:

* **Dry-run preview, explicit planning on execute.** `execute=False` previews ready work and the inventory-derived chain without creating tasks or changing session state. `execute=True` refuses a non-`running` investigation (`ValueError`) and returns without planning more work while any task is stuck (`find_stuck_tasks`), telling the operator to recover first. Once clear, it calls `plan_inventory_research_tasks()` before asking `plan_next_tasks()` for executable work.
* **Budgets respected, never bypassed.** `plan_next_tasks` slices to `Investigation.max_tasks` and `create_task` enforces the task and LLM caps, so a cycle can only propose and run what the budget allows.
* **Stop at safety gates and failures.** Proposed tasks run in deterministic creation order; the first failure stops the cycle. A verification task remains pending unless the caller supplies a transient plan and `approve_verification=True`; the CLI additionally requires `--yes --lab --approve-verification --verification-plan-stdin` for that path. The verifier remains lab-only.
* **Flush only, no hypothesis.** The helper never commits and never writes `Hypothesis.status`; `scripts/run_supervised_investigation.py` is the operator entry point that commits once at the end.

`scripts/run_supervised_investigation.py <id>` is a dry run (prints ready tasks and inventory task proposals, exit 0, no writes). `--yes` runs one cycle; `--yes --max-cycles N` (N capped at 5) runs at most N cycles in one process, re-planning between them and stopping on no work, a verification refusal, a stuck task, or a failure. Execution mode commits task planning together with each task's running checkpoint before dispatch; dry-run mode stays read-only. Research brief generation is offline; hypothesis generation may call the configured LLM only when the operator explicitly executes that task. Passive recon may perform DNS lookups only when explicitly executed with current scope authorization. No scheduler, daemon, or automatic finding promotion exists.

### Inventory planning, research, and verification handoff (Missions 004–006)

`orchestration.inventory_planner.plan_inventory_research_tasks()` consumes stored `endpoint_inventory` observations only. It validates HTTP(S) URL shape, exact asset-host consistency, and current program scope; it defers incomplete or failed upstream work and enforces task/LLM budgets before creating a dependency chain: optional completed inventory tasks → `research_brief` → `hypothesis_generation` → manual `hypothesis_review` tasks. Repeated planning reuses existing records. SQLite planning acquires an immediate transaction-scoped write lock before reading inventory, serializing concurrent planners; stable nullable `Task.dedupe_key` values and a unique index enforce duplicate prevention at the database boundary. `preview_inventory_research_tasks()` returns the proposal shape under `session.no_autoflush` without writes.

Repeated endpoint URLs (same scheme, host, effective port, path, and query; fragments ignored) produce one review task, and the planner reports the redundant observation ids. Review order is deterministic: HTTP 200/401/403 context first, successful redirects/other successful statuses next, and remaining statuses last. The proposal includes a reason stating that status is context and not proof or severity. Researcher brief observation cards identify missing provenance, response size, and body digest metadata explicitly; they do not infer that an evidence gap proves a vulnerability.

`orchestration.task_runner.run_task()` dispatches existing passive DNS recon, the offline researcher brief, hypothesis generation, and the lab-only verifier. Recon requires the caller's scope authorizer; the brief makes no network or LLM call; generation is the existing LLM caller. Verification plan JSON is bounded, bound to one `hypothesis_id`, and read from stdin by `verification.plan_input`; request headers remain transient, request errors are not echoed, and evidence URL query strings/fragments are redacted before storage. Explicit approval and lab-mode opt-in are independently required, and one approval executes at most one verification task per invocation. `hypothesis_review` remains operator-controlled, and only the existing promotion gate can create a finding.

Before dispatching a network task, the task runner intersects the invocation's authorizer with the program scope freshly loaded from the database. If current scope denies an inventory, recon, or verification target, the pending task is refused before it is marked running. Verification plan targets must also match the hostname of the hypothesis asset; program-level authorization alone cannot attach evidence from another asset to that hypothesis. Crash-recovery reasons are bounded and reject common credential-shaped values before they enter task history.

## Data Flow

1. `gateway.program_config.load_program()` loads and validates YAML program metadata and scope patterns.
2. `gateway.scope_policy.ScopePolicy` canonicalizes exact and `*.` hostname patterns. Exclusions take precedence over all authorizations.
3. `gateway.resolver.authorized_resolve()` rejects out-of-scope hostnames before delegating to `gateway.dns_pin.pin_url()`. The pinning layer validates the URL, authorizes it again, resolves it, and rejects any non-public answer. The adapter returns one validated IP.
4. `workers.recon.passive_discover()` calls the authorized resolver before querying A, AAAA, MX, and TXT records through dnspython. Each record query consumes one `RateLimiter` allowance; when the allowance is exhausted, recon stops and returns observations already collected. It performs DNS lookups only.
5. `workers.storage.store_observations()` creates or reuses an asset within an investigation and adds observations to the caller's SQLAlchemy session. The caller owns commit and rollback.
6. `data.models` defines Program, Investigation, Task, Asset, and Observation. `data.db.initialize_fresh_database()` creates the schema only for an empty database; runtime entry points validate readiness and do not initialize or migrate.
7. `verification.http_probe.probe_endpoint()` authorizes and pins a URL, sends one GET directly to the selected pinned IP, and returns status, sanitized/truncated headers, elapsed time, raw response-body byte count, and a SHA-256 hash of those bytes. The raw body is not retained; redirects are not followed; the request has an absolute deadline and a 1 MiB response limit.
8. `verification.diff_check.compare_requests()` runs two independent authorized probes and reports only deterministic status, body-hash, content-length, and header differences. It does not interpret their security meaning; callers may pass distinct request headers, which are not included in the diff result.
9. `verification.evidence.store_diff_evidence()` links an allowlisted diff result to a `Hypothesis` and its `Asset` via the hypothesis relationship. Hypotheses remain unverified by default; storing evidence does not classify a vulnerability. Durable evidence redacts URL query strings and fragments; request headers are never persisted, and sensitive response headers are filtered by the probe layer.
10. `verification.run_verification.run_verification()` is a human-initiated, single-shot composition of hypothesis lookup, two-probe comparison, and evidence persistence. It never changes hypothesis status or commits the caller's transaction.
11. `verification.http_probe.probe_lab_target()` is the single lab transport. It requires an explicit `allow_private_network=True` opt-in and a target marked `is_lab_target=True`, then delegates to the same private pinned transport used by `probe_endpoint()`; it never resolves or authorizes on its own.
12. `verification.lab_verification.run_lab_verification()` is a separate manual-only path that explicitly opts into `pin_lab_url()` for both targets and uses the guarded `probe_lab_target()` transport, diff builder, and evidence writer. It is not called by `run_verification()`, workers, or recon.
13. `intelligence.observation_summary.summarize_observations()` turns one asset's stored observations into an `ObservationSummary` split in two: `text` holds only system-derived scalars (URLs, hashes, counts, status codes, record types, fixed field vocabulary) and `untrusted` holds every string that originated from the target, each wrapped as a labeled `UntrustedText`. Unknown or mapping-valued keys, such as header names, are folded into untrusted items referenced by numeric position, so no target-originated text ever becomes a bare prompt string or a source label. An asset with no observations produces a sensible empty-case summary instead of an error.
14. `intelligence.hypothesis_generation.generate_hypotheses()` is the first live caller of `intelligence.llm_client.generate_completion()`. It loads the asset's observations, builds the summary, passes only `summary.text` as the user prompt plus `summary.untrusted` as marked untrusted context, parses `category: description` lines into `Hypothesis` rows, and `session.add()`/`session.flush()`es them with the hardcoded status `"unverified"`. It never commits, never probes, and lets `LLMClientError` propagate. An empty observation set means no model call and an empty list.
15. `intelligence.prioritization.prioritize_hypotheses()` is a pure, offline sort of already-loaded rows: only rows whose status is exactly `"unverified"` are candidates, ordered by category weight (`access_control`/`idor` first), then newest first, then row id, category, and description. No session, network, LLM, or mutation of its input.
16. `verification.verdict_checker.check_verdict()` is a pure function over one stored observation mapping and one `VerdictClaim`. It recomputes the compared flags from the recorded numbers rather than trusting any stored flag, returns `supported` / `refuted` / `inconclusive` with machine-readable reason codes, and fails closed to `inconclusive` on thin, malformed, or internally contradictory data. A control claim can never be `supported`; the only control outcomes are `refuted` (it matched, so it cannot discriminate) and `inconclusive` (`control_discriminated`).
17. `verification.run_hypothesis_verification.run_hypothesis_verification()` executes a human-authored `VerificationTestPlan` of `RequestPair`s through the guarded `probe_lab_target()` transport only. It validates the whole plan (loopback-lab URLs, non-empty endpoints, claim/control pairing) before the first request, authorizes and pins **every** target in the plan before the first request, probes every control pair before recording any claim, stores claim verdicts plus one diff evidence row with `flush()`, and never calls `commit()`. It never writes `Hypothesis.status`; request headers remain transient, sensitive response headers are filtered, and durable evidence URLs omit query strings and fragments.
18. `verification.verdict_integrity.verify_verdict()` binds a stored `Verdict` to the evidence row it judged, the hypothesis, and the recorded target URLs, and re-derives the judgement from the stored bytes. It is pure (no session, network, model, or clock) and returns a structured check with a reason code rather than raising. `digest_for()` computes the digest the writer stores; `evidence_digest()` hashes the canonical evidence content. The promotion gate and the report loader both call it, so a verdict that was edited, hand-written, or rebound to other evidence is rejected wherever it is consumed.
19. `verification.finding_promotion.promote_to_finding()` is the human-only promotion gate and the only status writer in the project. It requires a named `approved_by`, an `unverified` hypothesis, at least one supported non-control verdict, and evidence owned by that hypothesis; it refuses if any verdict is `refuted` or fails its integrity check (hand-written, edited, or bound to other evidence); it sets the status to `verified`, creates the `Finding`, and writes a `PromotionAudit` row — all with `flush()`, leaving the commit to the caller.
20. `verification.finding_report.render_finding_report()` is a pure deterministic Markdown renderer over a `FindingReportContext` loaded by `collect_finding_context()`. It renders the local-lab banner, finding/asset metadata, reproduction steps, the recorded status/bytes/hash comparison, the verdict table with reason codes, the recomputed verdict-integrity line, a bounded impact paragraph, explicit limitations, and the approval trail. The loader verifies every verdict against its evidence first, and the renderer refuses to render when the context has no supported verdict or no evidence.
21. `verification.report_package.build_report_package(session, finding_id, out_path)` is a read-only zip exporter: it loads the finding through the same integrity-verifying `collect_finding_context()`, renders the Markdown, and writes `report.md` plus a `manifest.json` of provenance (finding/hypothesis/investigation ids, evidence/control observation ids, verdict ids, integrity-digest prefixes, approver, promotion timestamp). It never writes, promotes, or commits to the database, and the manifest contains no credential or header value because none is ever stored. `scripts/package_finding.py` is the operator entry point; it opens SQLite read-only and refuses a missing finding or a tampered record rather than emitting a partial zip.

## Security Boundaries

- Scope checks are deny-by-default; only explicit exact or wildcard entries authorize hostnames.
- Excluded patterns always win, including when a broader wildcard is authorized.
- New hostname resolution should go through `gateway.resolver.authorized_resolve()`, not call `gateway.dns_pin` directly.
- `verification.http_probe` uses a per-probe Requests adapter to connect to a `pin_url()`-validated address while preserving the hostname for the HTTP Host header and TLS server name. Any future HTTP client must preserve this invariant; resolving the URL again in the client would reintroduce DNS rebinding risk.
- `verification.http_probe.probe_lab_target()` is the only supported lab transport and it is guarded: it rejects the request unless the caller passes `allow_private_network=True` and the target is lab-marked (`is_lab_target=True`, produced only by `pin_lab_url()`). `PinnedTarget.is_lab_target` defaults to `False`, so a public target can never satisfy the guard. It reuses `probe_endpoint()`'s pinned transport, keeping the Host/TLS/pinned-IP invariant in one module; `probe_endpoint()` remains the public-only entry point.
- Probe evidence omits sensitive authentication, cookie, token, credential, session, CSRF, and key headers and secret-shaped values; retained header values are bounded. Query values and fragments are redacted. Only the content-coded body hash and byte count are returned. Response decompression is disabled to keep the hash/length aligned with the body bytes represented by `Content-Length` when present.
- The deterministic diff layer has no vulnerability, severity, or likelihood conclusions. Extra request headers are used for the probe only and are never copied into comparison evidence.
- `Observation.hypothesis_id` is nullable so passive recon evidence can exist independently; verification evidence is linked to a hypothesis and inherits its asset ID from that hypothesis.
- `gateway.lab_mode.pin_lab_url()` is a standalone manual lab-only escape hatch. It requires the explicit `allow_private_network=True` argument, still enforces URL authorization, and returns a `LabPinnedTarget` marked `is_lab_target=True`. Normal workers and verification modules must not import it.
- Target-originated text never reaches the trusted `ObservationSummary.text` or its source labels. Labels use a fixed vocabulary plus numeric positions, and an unrecognized observation type is treated as fully untrusted (conservative default), which keeps prompt-injection content inside `UntrustedText` items instead of in model instructions.
- Generated hypotheses are suggestions for a human reviewer. `generate_hypotheses()` writes only the hardcoded `"unverified"` status, and the parser drops any `status`, `severity`, `confidence`, or `verified` line, so model output cannot promote its own claims. `prioritization` is fail-closed in the same spirit: anything not exactly `"unverified"` is excluded from ranking.
- `verification.verdict_checker.check_verdict()` is the only interpretation layer and it is pure: it takes the stored observation mapping, recomputes the compared flags from the recorded numbers, and returns `inconclusive` whenever the data is thin, malformed, internally contradictory, or lacks a discriminating control. Recorded flags are never trusted, and no control claim can yield `supported`, so a pair that returns the same bytes can never be promoted as a control result.
- The verification runner is gated four ways: it accepts only lab-marked targets via `probe_lab_target()`, it validates the entire plan before the first request, it authorizes and pins every target in the plan before the first request (so an out-of-scope target stops the run with no request sent), and it probes every control pair before it records any claim. A control that does not discriminate raises `SetupControlError` with nothing written. Request credentials are never stored, logged, or copied into evidence or reports.
- Every `Verdict` row carries an integrity digest binding the judgement to the evidence row id, its canonical evidence content, the hypothesis id, and the two recorded target URLs. `store_verdict()` refuses to write a row that fails the same `verify_verdict()` check its consumers apply, so the writer and the verifier cannot drift apart. Retained evidence and verdict rows cannot be updated through the ORM or direct SQLite SQL; the verdict digest remains a separate check against tampering or unsupported database access. A hand-written row cannot present a digest that re-derives from the bytes it cites.
- `verification.finding_promotion.promote_to_finding()` is the project's only writer of `Hypothesis.status` and its only creator of `Finding` rows; `tests/test_finding_promotion.py` asserts both properties across `verification/`, `intelligence/`, `gateway/`, and `data/`. Promotion requires a named human approver, refuses any refuted verdict, refuses any verdict that fails its integrity check, and records who, when, and what in `promotion_audit`.
- `verification.investigation_lifecycle` is the project's only writer of `Investigation.status`; `tests/test_investigation_lifecycle.py` asserts this across `verification/`, `intelligence/`, `gateway/`, and `data/`. It writes nothing else, flushes without committing, and cannot import the gateway, call a model, or touch a `Hypothesis` or `Finding`.
- `verification.investigation_tasks` is the project's only writer of `Task.status`, `Task.started_at`, and `Task.ended_at`; `tests/test_investigation_tasks.py` asserts this (and that the only `Investigation`/`Task` status writers are the two lifecycle modules) across `verification/`, `intelligence/`, `gateway/`, `data/`, `workers/`, and `scripts/`. An AST guard pins its imports to `datetime`, `sqlalchemy`, and the `Investigation`/`Task` models, so it cannot reach the gateway, a model, a transport, or the promotion gate.
- `verification.finding_report.collect_finding_context()` verifies every verdict against its evidence, hypothesis, and target before a report can be rendered, so an edited row cannot be presented as approved evidence. The renderer itself writes nothing: it renders only allowlisted, already-stored values, does not re-probe, call a model, read the clock, or dump raw observation JSON, and it carries a local-lab banner plus explicit "local lab only / not a severity assessment / machine-checked, not human-confirmed" limitations.
- `verification.finding_report` renders only allowlisted, already-stored values: it does not re-probe, re-judge, call a model, read the clock, or dump raw observation JSON. Reports carry a local-lab banner and explicit "local lab only / not a severity assessment / machine-checked, not human-confirmed" limitations.
- `verification.endpoint_inventory_collector.collect_seed_inventory()` sends at most one guarded request per authorized seed candidate, commits nothing, passes no request headers, and reuses the guarded transports (`probe_endpoint()` publicly; with an explicit lab opt-in, `pin_lab_url()` then `probe_lab_target()`, with the whole candidate list pinned before the first probe). Its stored `endpoint_inventory` rows are asset-level context that no verdict may cite - see "Inventory observations are context, never verdict evidence".
- Recon is passive DNS only. The HTTP probe is a single explicit request and does not follow redirects. No port scanning or autonomous actions are part of V1.
- `programs/example_program.yaml` uses `.test`, a reserved testing domain; it is not a live target configuration.

## Validation

Run the suite with the project environment:

```sh
python -m pytest -q
```

The V1 end-to-end test mocks the pinning and DNS boundaries and uses in-memory SQLite. Before live use, a human must review `gateway/dns_pin.py` and configure only program-authorized domains.

The V3 tests are offline as well: they use in-memory SQLite and a fake or frozen lab transport, so no test in the suite makes a network request. The live lab path is exercised only by the manual operator script and by a deliberate human-run verification. The verdict-integrity tests tamper with each binding in turn - an edited field, an edited evidence row, a digest recomputed over the wrong evidence, another hypothesis, or another target - and assert that both the promotion gate and the report loader reject the row; a static guard asserts the judge and the verifier stay offline and session-free.

## Intelligence API Configuration

`intelligence.llm_client` is API-only DeepSeek infrastructure and has exactly one caller in an investigation flow: `intelligence.hypothesis_generation.generate_hypotheses()`. It reads `DEEPSEEK_API_KEY` from the process environment; no other module imports it, and nothing calls it at import time, on a schedule, or in a loop. Provide the key through a local secret manager or environment configuration; never commit the key to this repository. Tokens are spent only when an operator deliberately runs generation, or by tests that mock the transport.

## Mission 004: endpoint-inventory-driven investigation planning

Missions 004–009 integrate the deterministic endpoint-inventory planner with the existing supervised cycle. Eligible stored endpoints are scope/host checked and turn into duplicate-safe research tasks with bounded budgets and valid dependencies. Dry-run preview is side-effect free; execution creates tasks, then dispatches only ready tasks. Passive DNS recon and the offline researcher brief are available through existing task dispatch. Hypothesis generation may use the configured LLM only when explicitly executed. Endpoint review, verification approval, and finding promotion remain human-controlled. Verification plans arrive through bounded stdin input, credentials are transient, and query strings/fragments are redacted from persisted diff evidence.

The Juice Shop basket comparison remains a separate operator-run local-lab task. The pipeline has no autonomous scheduler, public-target verification mode, finding promotion, or report submission.

`task_observations` records structured `input` and `output` links for task
dispatch. Inventory and recon record produced observations; research briefs and
hypothesis generation record observations they consume; verification records
the observations it produces. Planner-created manual review tasks link the
specific observation presented for review. SQLite rejects link updates and
deletion, rejects cross-investigation links, and schema readiness validates the
protection triggers. These links describe task execution context; they do not
upgrade supporting observations into verified vulnerability evidence.

Pre-existing observations are not assigned fabricated task links during
migration. If no relationship can be established from recorded data, task
provenance remains unknown rather than being inferred from a summary string.
`observation_fingerprints` stores a deterministic digest of canonical evidence
plus ownership/type context and an exact-duplicate pointer. A hash match is
confirmed against canonical payload bytes; duplicate rows remain stored and
auditable rather than being discarded.
