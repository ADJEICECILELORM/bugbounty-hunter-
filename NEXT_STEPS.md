# V1 Build Plan — Agentic Bug Bounty Hunter

**V1 scope per the original roadmap:** Program configuration, authorization checks, passive asset discovery, structured storage. Nothing autonomous yet — just the safe foundation.

## Status so far

- ✅ `gateway/dns_pin.py` + tests — DNS pinning, SSRF protection, redirect validation. **Needs human review of actual file contents before building on top (pending).**
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

All 8 tasks and `test_v1_e2e.py` pass. A manual live run against a real program-authorized domain remains unverified; review `gateway/dns_pin.py` and replace the reserved `.test` example with verified scope before live use.

## Controlled Verification Progress

- ✅ First building block: `verification/http_probe.py` sends one authorized GET over a pinned IP, preserves the hostname for Host/TLS, does not follow redirects, enforces an absolute deadline and 1 MiB body limit, hashes raw content-coded bytes without retaining them, strips sensitive headers, and truncates long header values.
- ✅ Deterministic comparison: `verification/diff_check.py` compares two independently authorized probes by status, body hash, length, and sanitized headers without making vulnerability judgments.
- ✅ Evidence persistence: `verification/evidence.py` stores explicit allowlisted diff/probe fields as an observation linked to an unverified hypothesis and its asset.
- ⚠️ Probe tests mock the transport. A live request must wait for human review and an explicitly authorized target.

## After V1

Per your roadmap, V2 is investigation intelligence (endpoint inventory, hypothesis generation) — but per Kimi's earlier point, consider swapping to **controlled verification** (V3 concepts) before hypothesis generation, since that's the harder and more valuable piece to get right early.
