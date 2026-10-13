# V1 Build Plan — Agentic Bug Bounty Hunter

**V1 scope per the original roadmap:** Program configuration, authorization checks, passive asset discovery, structured storage. Nothing autonomous yet — just the safe foundation.

## Status so far

- ✅ `gateway/dns_pin.py` + tests — DNS pinning, SSRF protection, redirect validation. **Human review of the actual file contents is done (see "DNS Pinning Review" below); no exploitable defect found, and 22 hardening cases were added.**
- ✅ Tasks 1–8 — Scope Policy, Program Config Loader, Authorized Resolver, Rate Limiter, PostgreSQL Schema, Passive Recon, Storage, and End-to-End Smoke Test
- ✅ Recon enforces the configured rate limit per DNS record query and preserves partial results when throttled.
- ⚠️ Live recon against a program-authorized domain has not been run. The example uses the reserved `.test` domain and integration tests mock DNS.

## Standing practices (apply every session, every tool)

- Point any new Cline/Copilot session at `ARCHITECTURE.md` instead of re-explaining the project
- Commit after every passing-tests milestone
- Default to cheap/Flash model tier; escalate to Pro/reasoner only for security-critical logic (scope policy, auth)
- Don't trust "tests pass" alone on security-sensitive modules — review the actual logic yourself, especially for check-then-use race conditions
- Update this doc's status section as you complete each piece

---

## Task 1 — Scope Policy (Layer 1 core)

> Create `gateway/scope_policy.py` with a `ScopePolicy` class holding: a list of authorized hostnames/domains, a list of excluded hostnames/domains, and a method `is_authorized(hostname: str) -> bool` returning True only if the hostname matches an authorized entry AND does not match an excluded entry (excluded always wins, even over a broader authorized wildcard). Support exact matches and wildcard subdomain matches (`*.example.test`). Write pytest tests covering: exact match, wildcard match, excluded subdomain overriding authorized wildcard, unlisted hostname defaults to unauthorized. Run tests, fix failures.

## Task 2 — Program Config Loader (Layer 1)

> Create `gateway/program_config.py` with a function `load_program(path: str) -> dict` that reads a YAML file describing a bug bounty program (fields: `name`, `authorized_scope: list[str]`, `excluded_scope: list[str]`, `rate_limit_per_minute: int`, `max_investigation_hours: int`) and returns a validated dict. Raise a clear exception if required fields are missing or malformed. Create an example `programs/example_program.yaml`. Write pytest tests for: valid file loads correctly, missing required field raises, malformed YAML raises. Run tests, fix failures.

## Task 3 — Wire Scope Policy to DNS Pin (connects Task 1 to existing gateway)

> In `gateway/`, create `gateway/resolver.py` with a function `authorized_resolve(hostname: str, policy: ScopePolicy) -> str` that first checks `policy.is_authorized(hostname)` — raise `UnauthorizedTargetError` if False — then calls `resolve_and_pin` from `dns_pin.py` and returns the pinned IP. This is the single entry point anything else in the system should use to resolve a hostname; nothing should call `dns_pin.py` directly. Write pytest tests: authorized hostname resolves successfully, excluded hostname raises `UnauthorizedTargetError` before any DNS lookup happens (mock dns_pin to confirm it's never called in the rejected case). Run tests, fix failures.

## Task 4 — Rate Limiter (Layer 1, from program config)

> Create `gateway/rate_limiter.py` with a `RateLimiter` class taking `requests_per_minute: int`, with a method `allow() -> bool` that returns True if a request is permitted under the limit (sliding window or token bucket, your choice) and False otherwise. Write pytest tests: requests under the limit are allowed, requests over the limit are rejected, limit resets after the time window passes (you can mock time for this). Run tests, fix failures.

## Task 5 — PostgreSQL Schema (Layer 7 — minimal V1 version)

> Using SQLAlchemy, create `data/models.py` with these tables: `Program` (id, name, authorized_scope JSON, excluded_scope JSON, rate_limit, created_at), `Investigation` (id, program_id FK, status, started_at, ended_at), `Asset` (id, investigation_id FK, hostname, discovered_at), `Observation` (id, asset_id FK, observation_type, data JSON, created_at). Create `data/db.py` with a function `init_db(connection_string: str)` that creates all tables. Write a pytest test using an in-memory SQLite db (for test speed) that creates a Program, an Investigation linked to it, an Asset linked to that, and an Observation linked to that — then queries them back and asserts the relationships hold. Run tests, fix failures.

## Task 6 — Passive Recon Worker (Layer 4 — minimal V1 version)

> Create `workers/recon.py` with a function `passive_discover(hostname: str, policy: ScopePolicy) -> list[dict]` that: calls `authorized_resolve` from `gateway/resolver.py` first (raises if unauthorized), then performs passive-only discovery (DNS records: A, AAAA, MX, TXT — use Python's `dns.resolver` from the `dnspython` package, no active scanning) and returns a list of observation dicts (e.g. `{"type": "dns_record", "record_type": "A", "value": "..."}`). Write pytest tests: authorized hostname returns observations (mock the DNS lookups), unauthorized hostname raises before any lookup happens. Run tests, fix failures. Add `dnspython` to a `requirements.txt` file if one doesn't exist yet.

## Task 7 — Wire Recon Worker to Storage

> Create `workers/storage.py` with a function `store_observations(investigation_id: int, asset_hostname: str, observations: list[dict], session)` that takes the output of `passive_discover`, creates or finds the matching `Asset` row for `asset_hostname` under `investigation_id`, and inserts each observation as an `Observation` row linked to that asset. Write a pytest test using an in-memory SQLite session: call with sample observations, then query the db and confirm the Asset and Observation rows exist correctly. Run tests, fix failures.

## Task 8 — End-to-End V1 Smoke Test

> Create `tests/test_v1_e2e.py` that: loads an example program config (Task 2), creates a `ScopePolicy` from it, creates an in-memory db with a `Program` and `Investigation` row, runs `passive_discover` against an authorized test hostname (mock the actual DNS calls), stores the results via `store_observations`, then queries the db to confirm an `Asset` and at least one `Observation` exist. Also add a negative case: an excluded hostname should raise before reaching storage. This test proves the full V1 loop works end to end. Run it, fix any integration issues between the modules.

---

## V1 complete when

All 8 tasks and `test_v1_e2e.py` pass. A manual live run against a real program-authorized domain remains unverified; `gateway/dns_pin.py` has been reviewed (see "DNS Pinning Review" below), so the remaining step is to replace the reserved `.test` example with verified scope before live use.

## Controlled Verification Progress

- ✅ First building block: `verification/http_probe.py` sends one authorized GET over a pinned IP, preserves the hostname for Host/TLS, does not follow redirects, enforces an absolute deadline and 1 MiB body limit, hashes raw content-coded bytes without retaining them, strips sensitive headers, and truncates long header values.
- ✅ Deterministic comparison: `verification/diff_check.py` compares two independently authorized probes by status, body hash, length, and sanitized headers without making vulnerability judgments.
- ✅ Evidence persistence: `verification/evidence.py` stores explicit allowlisted diff/probe fields as an observation linked to an unverified hypothesis and its asset.
- ✅ Human-initiated verification: `verification/run_verification.py` performs one comparison and evidence write without changing hypothesis status or committing.
- ✅ Manual local-lab adapter: `verification/lab_verification.py` requires `allow_private_network=True` for each run and remains separate from normal investigation flows.
- ✅ Live local-lab smoke run: two read-only GETs to Juice Shop's `/rest/products/search?q=apple` returned HTTP 200 with matching hashes; a `diff_check` observation was stored in in-memory SQLite while the hypothesis remained `unverified`.
- ✅ Lab transport API cleanup: `verification/lab_verification.py` now depends on the stable, guarded `verification.http_probe.probe_lab_target()` (plus the public `validate_timeout`). That API requires both `allow_private_network=True` and a lab-marked target, reuses the same pinned transport as `probe_endpoint()`, and cannot become a general private-IP bypass; the private `_probe_pinned_target`/`_validate_timeout` helpers are no longer imported by any lab caller. Isolation tests assert the lab transport is reachable only from `lab_verification.py` and that `probe_endpoint()` still rejects non-public targets.
- ✅ Manual lab-only experiment hardening: `scripts/lab_basket_access_experiment.py` fails closed on setup quality *before* any evidence exists. `validate_setup_controls` requires both `/rest/basket/<id>` reads to return HTTP 200, A's basket to contain the seeded product, and B's basket to be empty and distinguishable from A's; `require_unverified` re-asserts the hypothesis is still `unverified` after call 1 and again immediately before `session.commit()`. Its pure gates (`validate_setup_controls`, `parse_product_ids`, `exact_url_authorizer`, `require_unverified`) are unit-tested in `tests/test_lab_basket_access_experiment.py` (32 cases, including that `main()` writes no evidence and never reaches the runner when the controls are wrong, and that the unreachable path exits with the exact `docker run` line instead of making a request). The script itself is never executed by the suite.
- ✅ Dormant Layer 8 client: `intelligence/llm_client.py` returns text suggestions only and has no investigation-flow callers; target-originated context is explicitly marked untrusted and bounded.
- ⚠️ Broader or authenticated verification still requires an explicitly approved target and test accounts; this smoke run tested only a public read-only lab endpoint. The authenticated two-account basket comparison is written and gate-tested but has not been run, because nothing is listening on `127.0.0.1:3000`. That is the **only** remaining blocker for this step: the script now reports it as `exit=1` with `LAB_START_COMMAND` and creates no database file, account, or row.
- ▶️ **Lab start (user-run, one line):** `sudo docker run --rm -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop`, then `curl -sS -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:3000/` (expect HTTP 200), then `venv/bin/python scripts/lab_basket_access_experiment.py` (run deliberately, once). `--rm --name juice-shop` are the only additions to the upstream command; the binding stays loopback-only. On this host the line must be run by you: user `ace` is not in the `docker` group, there is no rootless socket, and `sudo` requires an interactive password. Stop the lab with `sudo docker stop juice-shop`.

## DNS Pinning Review (completed)

Human review of the actual `gateway/dns_pin.py` contents (not just its passing tests), per the standing practice of distrusting green tests on security-sensitive modules. **Result: no exploitable defect found** — the SSRF/rebinding invariants hold. Verified properties:

- **Fail-closed ordering.** `pin_url()` validates the URL, calls `authorize(normalized_url)`, and only then resolves. An out-of-scope URL is rejected before any DNS query, so scope cannot be probed via resolution side effects.
- **Single parser, no differential.** The hostname derived once by `_parse_url()` is the same value used for authorization, resolution, the HTTP `Host` header, and the TLS server name. There is no second parser to disagree with, so authority-confusion tricks (`https://good.com\@evil.com/`, `user@host`, fragments such as `https://example.com#@evil.com/`) cannot redirect the request.
- **Strict answer validation.** *Every* resolved address must be `is_global`; a single private answer rejects the whole target, rather than filtering it out (which would permit rebinding onto the surviving private answer). Verified to cover IPv4 loopback, IPv6 loopback, IPv4-mapped loopback (`::ffff:127.0.0.1`), scoped link-local (`fe80::1%eth0`), link-local/metadata (`169.254.169.254`), carrier-grade NAT (`100.64.0.1`), and `0.0.0.0`. Public IPv6 answers are accepted.
- **No DNS-rebinding (TOCTOU) window.** The validated IP is carried in `PinnedTarget.addresses`; `verification/http_probe.py` connects to that literal IP (`create_connection((self._pinned_ip, self.port))`) with `max_retries=0`, and the URL is never re-resolved while `Host`/SNI stay bound to the hostname. The checked value and the used value are the same object.
- **Redirects are re-authorized.** `validate_redirect()` re-runs the full authorize + resolve + validate path on `urljoin(current, location)`, and the probe disables redirects entirely (`allow_redirects=False`).
- **Lab mode stays separate.** `pin_lab_url()` is the only path that skips the public-IP check; it still calls the authorizer, marks the target `is_lab_target=True`, requires `allow_private_network=True`, and is unreachable from public flows.

Documented, non-exploitable observations:

- The default port is not canonicalized in the `authorize()` input, so `https://example.com/` and `https://example.com:443/` are presented as different strings. This is fail-closed for exact-URL allowlists (the variant is rejected rather than widened) and is now locked in by `test_pin_url_does_not_canonicalize_the_default_port`.
- Authorization ultimately trusts the *resolved* address being global, so a caller-supplied `resolver` that returns a public IP for a non-canonical host (e.g. the decimal form `2130706433`) is trusted. The default `_system_resolver` is safe because `getaddrinfo` returns the numeric interpretation, which then fails the `is_global` check. Do not pass a permissive resolver.

`tests/test_dns_pin.py` grew 8 → 30 cases to pin the properties above so a future edit cannot silently weaken them.

## After V1

Per your roadmap, V2 is investigation intelligence (endpoint inventory, hypothesis generation) — but per Kimi's earlier point, consider swapping to **controlled verification** (V3 concepts) before hypothesis generation, since that's the harder and more valuable piece to get right early.
