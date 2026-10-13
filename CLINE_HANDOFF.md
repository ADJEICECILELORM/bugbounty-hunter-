# Project 001 Handoff for Cline

Use `ARCHITECTURE.md` for the current module/data flow and `NEXT_STEPS.md` for the longer roadmap. Continue the existing architecture; do not redesign the project or wire dormant components into autonomous flows without an explicit task.

## Current Checkpoint

- Branch: `main`
- Last verified code commits: `050748e` (`Review gateway/dns_pin.py and pin its SSRF invariants with tests`) and `8aa96b4` (`Add manual lab-only basket-access experiment script`), preceded by `c7bb2b7` (`Extract guarded lab-only probe transport API`).
- The worktree is clean and `origin/main` matches the pushed history: `bfb0b1e`, which follows `93808c8`, `050748e`, and `8aa96b4`.
- Last full test run: 107 passed (+22 `dns_pin` hardening cases over the previous 85).

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
- `scripts/lab_basket_access_experiment.py` is a manual, lab-only operator script (not part of the package or the test suite). It registers two disposable local Juice Shop accounts, seeds one basket, and exercises the guarded lab transport end to end via two `run_lab_verification()` calls, writing evidence only to the separate `lab_evidence.db`. Credentials and JWTs stay in memory; the hypothesis status is never changed.

## Live Lab Check

The user started OWASP Juice Shop in Docker with `sudo` on `127.0.0.1:3000`. Docker CLI access for the normal user is permission-limited; do not add the user to the `docker` group without explicit approval (that group grants root-equivalent access).

A real, read-only lab smoke run compared `http://127.0.0.1:3000/rest/products/search?q=apple` with itself using `run_lab_verification()`. Both responses were HTTP 200 with matching body hashes. A `diff_check` Observation was persisted in an in-memory SQLite database; the Hypothesis remained `unverified`, and the transaction stayed caller-owned. This was not authenticated IDOR testing, did not persist evidence beyond the in-memory run, and is not a confirmed vulnerability.

That live run found and fixed an urllib3 API mismatch: call `response.raw.stream(_BODY_READ_SIZE, decode_content=False)` with the byte amount positional. Keep raw content-coded hashing, the deadline, and the 1 MiB cap.

## Lab Transport API Cleanup (resolved)

Resolved in `c7bb2b7`. `verification/lab_verification.py` no longer imports the private `_probe_pinned_target` / `_validate_timeout` helpers. It now uses the stable, guarded `verification.http_probe.probe_lab_target()` (plus the public `validate_timeout`). That transport requires both `allow_private_network=True` and a target marked `is_lab_target=True` (a new `PinnedTarget` field that defaults to `False`, so public targets can never satisfy it), then delegates to the same private pinned transport used by `probe_endpoint()`. It therefore cannot become a general private-IP request path, and `probe_endpoint()` / `run_verification()` remain public-only. Isolation tests assert the lab transport is reachable only from `lab_verification.py` and that `probe_endpoint()` still rejects non-public targets.

## DNS Pinning Review (completed)

Audited the actual `gateway/dns_pin.py` contents (not merely its tests) in `050748e`. **No exploitable defect found**; the SSRF/rebinding invariants hold: `authorize()` runs before any resolution, one `urlsplit`-derived hostname is shared by authorization/resolution/Host/SNI (so no parser differential), *every* resolved answer must be `is_global`, and the validated literal IP is pinned with `max_retries=0` and never re-resolved (no TOCTOU window). Two non-exploitable observations are documented: the default port is not canonicalized in the `authorize()` input (fail-closed for exact-URL allowlists), and a caller-supplied permissive `resolver` would be trusted. `tests/test_dns_pin.py` grew 8 → 30 cases to pin these properties. Full write-up is in `NEXT_STEPS.md` ("DNS Pinning Review").

## Next Work

1. ✅ Resolved in `c7bb2b7` (guarded `probe_lab_target()` lab transport). Normal-path, lab-path, and full-suite tests all pass.
2. ✅ Resolved in `050748e` (audited `gateway/dns_pin.py`, added 22 hardening tests, recorded the review).
3. **Held at the user's request — prepared but not run.** `scripts/lab_basket_access_experiment.py` is ready and locally validated (compiles; the exact-URL authorizer rejects every non-allowlisted URL; missing `allow_private_network=True` is rejected). The run waits on the local lab being started: `http://127.0.0.1:3000` was unreachable and Docker requires an interactive `sudo` password.
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