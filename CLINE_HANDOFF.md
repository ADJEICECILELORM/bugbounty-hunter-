# Project 001 Handoff for Cline

Use `ARCHITECTURE.md` for the current module/data flow and `NEXT_STEPS.md` for the longer roadmap. Continue the existing architecture; do not redesign the project or wire dormant components into autonomous flows without an explicit task.

## Current Checkpoint

- Branch: `main`
- Last verified code commit: `7d29fb7` (`Fail closed on malformed lab basket responses`), with this handoff update pushed immediately after it.
- The worktree is clean and `origin/main` matches the pushed history.
- Last full test run: 139 passed, of which `tests/test_lab_basket_access_experiment.py` covers 32 gate cases (137/30 before this session's two additions).

## Project Goal

Build Project 001 as a persistent, policy-governed bug bounty research system, incrementally through V1–V6. The design includes governance, supervision, planning, specialized workers, a controlled gateway, evidence/events, persistent state, model routing, reporting, and human controls. These are architectural goals, not all implemented capabilities. Preserve the user's design and add tested vertical slices rather than attempting a broad rewrite.

## Implemented

- V1 foundation: program YAML, exact/wildcard scope policy with exclusions taking precedence, public-IP DNS pinning, authorized resolver, per-query sliding-window rate limiting, passive A/AAAA/MX/TXT recon, SQLAlchemy Program/Investigation/Asset/Observation/Hypothesis models, and SQLite-tested evidence storage.
- Controlled verification: `verification/http_probe.py` makes one authorized pinned GET, preserves hostname for Host/TLS, disables redirects/retries, enforces an absolute request deadline and 1 MiB response cap, hashes raw content-coded bytes, sanitizes response headers, and returns typed network errors.
- `verification/diff_check.py` performs deterministic response comparison; it makes no vulnerability/severity judgment.
- `verification/evidence.py` stores an explicit allowlist of diff/probe fields against a hypothesis and derives `asset_id` from that hypothesis.
- `verification/run_verification.py` is a single-shot human-invoked flow. It fails fast on missing hypotheses, stores evidence, never changes hypothesis status, and never commits the caller's session.
- `gateway/lab_mode.py` is an explicit private-network pinning escape hatch. It requires `allow_private_network=True`, still invokes the authorizer, returns `LabPinnedTarget(is_lab_target=True)`, and is not imported by normal workers or public verification paths.
- `verification/lab_verification.py` is the separate manual lab flow; it probes through the guarded `verification/http_probe.probe_lab_target()` lab transport (see below).
- `intelligence/llm_client.py` is dormant, API-only DeepSeek infrastructure. It reads `DEEPSEEK_API_KEY` from the environment, bounds and marks untrusted target text, returns text only, and has no investigation-flow callers. Do not wire it into a live flow yet.
- `scripts/lab_basket_access_experiment.py` is a manual, lab-only operator script (not part of the package; the suite never executes it). It registers two disposable local Juice Shop accounts, seeds one basket, and exercises the guarded lab transport end to end via two `run_lab_verification()` calls, writing evidence only to the separate `lab_evidence.db`. Credentials and JWTs stay in memory; the hypothesis status is never changed. It fails closed on setup quality: `validate_setup_controls()` requires both basket reads to be HTTP 200, A's basket to contain the seeded product, and B's basket to be empty and distinguishable from A's — all before any hypothesis or evidence row exists — and `require_unverified()` re-asserts `unverified` after call 1 and again immediately before `commit()`. Those pure gates are unit-tested in `tests/test_lab_basket_access_experiment.py`. When the target is down it exits 1 at the reachability check (before any account or row is created) and prints `LAB_START_COMMAND`, the exact `docker run` line below, so the fail-closed path also tells the operator how to start the lab.

## Live Lab Check

The user started OWASP Juice Shop in Docker with `sudo` on `127.0.0.1:3000`. Docker CLI access for the normal user is permission-limited; do not add the user to the `docker` group without explicit approval (that group grants root-equivalent access).

Verified on the current machine: the `docker` CLI is present (29.1.3), but its only endpoint is `unix:///var/run/docker.sock` (`root:docker`, mode `660`), user `ace` is **not** in the `docker` group (`docker:x:116:` has no members), there is no rootless socket, and `sudo` requires an interactive password. So the container can only be started by the user. Start, verify, and stop the lab with:

```sh
sudo docker run --rm -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:3000/      # expect HTTP 200
venv/bin/python scripts/lab_basket_access_experiment.py                     # run deliberately, once
sudo docker stop juice-shop                                                 # --rm removes it
```

Upstream (`pwning.owasp-juice.shop`, "Docker image") documents `docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop`; `--rm --name juice-shop` are the only additions. The binding stays loopback-only, matching the hard-coded `BASE_URL` in the script, and `test_lab_start_command_keeps_the_target_on_loopback` fails if that ever changes.

A real, read-only lab smoke run compared `http://127.0.0.1:3000/rest/products/search?q=apple` with itself using `run_lab_verification()`. Both responses were HTTP 200 with matching body hashes. A `diff_check` Observation was persisted in an in-memory SQLite database; the Hypothesis remained `unverified`, and the transaction stayed caller-owned. This was not authenticated IDOR testing, did not persist evidence beyond the in-memory run, and is not a confirmed vulnerability.

That live run found and fixed an urllib3 API mismatch: call `response.raw.stream(_BODY_READ_SIZE, decode_content=False)` with the byte amount positional. Keep raw content-coded hashing, the deadline, and the 1 MiB cap.

## Lab Transport API Cleanup (resolved)

Resolved in `c7bb2b7`. `verification/lab_verification.py` no longer imports the private `_probe_pinned_target` / `_validate_timeout` helpers. It now uses the stable, guarded `verification.http_probe.probe_lab_target()` (plus the public `validate_timeout`). That transport requires both `allow_private_network=True` and a target marked `is_lab_target=True` (a new `PinnedTarget` field that defaults to `False`, so public targets can never satisfy it), then delegates to the same private pinned transport used by `probe_endpoint()`. It therefore cannot become a general private-IP request path, and `probe_endpoint()` / `run_verification()` remain public-only. Isolation tests assert the lab transport is reachable only from `lab_verification.py` and that `probe_endpoint()` still rejects non-public targets.

## DNS Pinning Review (completed)

Audited the actual `gateway/dns_pin.py` contents (not merely its tests) in `050748e`. **No exploitable defect found**; the SSRF/rebinding invariants hold: `authorize()` runs before any resolution, one `urlsplit`-derived hostname is shared by authorization/resolution/Host/SNI (so no parser differential), *every* resolved answer must be `is_global`, and the validated literal IP is pinned with `max_retries=0` and never re-resolved (no TOCTOU window). Two non-exploitable observations are documented: the default port is not canonicalized in the `authorize()` input (fail-closed for exact-URL allowlists), and a caller-supplied permissive `resolver` would be trusted. `tests/test_dns_pin.py` grew 8 → 30 cases to pin these properties. Full write-up is in `NEXT_STEPS.md` ("DNS Pinning Review").

## Next Work

1. ✅ Resolved in `c7bb2b7` (guarded `probe_lab_target()` lab transport). Normal-path, lab-path, and full-suite tests all pass.
2. ✅ Resolved in `050748e` (audited `gateway/dns_pin.py`, added 22 hardening tests, recorded the review).
3. **Held at the user's request — prepared, gate-tested, but not run.** `scripts/lab_basket_access_experiment.py` now fails closed on setup quality and asserts the hypothesis is still `unverified` before `commit()`. Its gates have 32 unit tests (full suite `139 passed`), and running it against the down lab aborts cleanly at the reachability check with no database file and no accounts created, now printing the exact start command. The live run still waits on the local lab: nothing is listening on `127.0.0.1:3000`, and the container can only be started by the user because Docker socket access requires an interactive `sudo` password (see "Live Lab Check" for the one-line command). Each run creates two new disposable accounts that remain in the local lab, so run it deliberately rather than casually.
4. When the user chooses to proceed: create two disposable local Juice Shop accounts and keep credentials only in memory/environment. Do not log or persist tokens. Use a specific user-approved endpoint/hypothesis; do not assume an IDOR exists or probe unrelated targets.
5. Run one comparison with distinct account headers through the lab-only flow, inspect sanitized diff evidence, and leave the hypothesis status unchanged for human review. If A and B receive identical bytes for A's populated basket while B's own empty basket differs, that is reproducible evidence of cross-account access **in the local lab only** — not an automatic status promotion and not a claim about any real program.
6. Only after the user approves, consider the separate hypothesis-generation module. The LLM remains dormant; target-originated text stays untrusted and must never trigger tools or writes directly.

## Safety and Workflow Rules

- Normal targets always go through `ScopePolicy` and `dns_pin.pin_url()`; exclusions win. Never weaken the public-IP guard in the normal path.
- Use lab mode only for the local lab and only with `allow_private_network=True`; never connect lab mode to recon, `compare_requests()`, or `run_verification()` implicitly.
- No autonomous scheduling, scanning, retries, report submission, or status promotion. Verification runs are explicit and single-shot; humans decide what results mean.
- Do not make requests to public targets unless the user provides and confirms explicit authorization and scope.
- Never put API keys, account passwords, or bearer tokens in repository files, test output, logs, or evidence.
- Before edits, inspect current status and nearby code. After changes, run focused tests then the full suite. Commit each passing milestone; push only after tests pass.

## Validation

Use the project venv:

```sh
venv/bin/python -m pytest -v
```