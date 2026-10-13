# Architecture

## V1 Scope

V1 provides program configuration, scope enforcement, safe DNS resolution, passive DNS discovery, relational storage, and an explicit single-request HTTP probe for controlled verification. It does not perform autonomous investigation or vulnerability checks. The current interface is a set of Python modules; there is no CLI or service entry point yet.

## V2 Scope

V2 adds investigation intelligence on top of V1: it summarizes the observations already stored for one asset, asks a model for candidate hypotheses through the first live `intelligence.llm_client` caller, and ranks those candidates with a deterministic rule. It produces **unverified candidates only**. No V2 module probes the network, runs a tool, changes a hypothesis status, or commits the caller's transaction; a human still has to invoke a verification flow before anything becomes evidence.

## Data Flow

1. `gateway.program_config.load_program()` loads and validates YAML program metadata and scope patterns.
2. `gateway.scope_policy.ScopePolicy` canonicalizes exact and `*.` hostname patterns. Exclusions take precedence over all authorizations.
3. `gateway.resolver.authorized_resolve()` rejects out-of-scope hostnames before delegating to `gateway.dns_pin.pin_url()`. The pinning layer validates the URL, authorizes it again, resolves it, and rejects any non-public answer. The adapter returns one validated IP.
4. `workers.recon.passive_discover()` calls the authorized resolver before querying A, AAAA, MX, and TXT records through dnspython. Each record query consumes one `RateLimiter` allowance; when the allowance is exhausted, recon stops and returns observations already collected. It performs DNS lookups only.
5. `workers.storage.store_observations()` creates or reuses an asset within an investigation and adds observations to the caller's SQLAlchemy session. The caller owns commit and rollback.
6. `data.models` defines Program, Investigation, Asset, and Observation. `data.db.init_db()` creates the schema and returns an engine.
7. `verification.http_probe.probe_endpoint()` authorizes and pins a URL, sends one GET directly to the selected pinned IP, and returns status, sanitized/truncated headers, elapsed time, raw response-body byte count, and a SHA-256 hash of those bytes. The raw body is not retained; redirects are not followed; the request has an absolute deadline and a 1 MiB response limit.
8. `verification.diff_check.compare_requests()` runs two independent authorized probes and reports only deterministic status, body-hash, content-length, and header differences. It does not interpret their security meaning; callers may pass distinct request headers, which are not included in the diff result.
9. `verification.evidence.store_diff_evidence()` links an allowlisted diff result to a `Hypothesis` and its `Asset` via the hypothesis relationship. Hypotheses remain unverified by default; storing evidence does not classify a vulnerability.
10. `verification.run_verification.run_verification()` is a human-initiated, single-shot composition of hypothesis lookup, two-probe comparison, and evidence persistence. It never changes hypothesis status or commits the caller's transaction.
11. `verification.http_probe.probe_lab_target()` is the single lab transport. It requires an explicit `allow_private_network=True` opt-in and a target marked `is_lab_target=True`, then delegates to the same private pinned transport used by `probe_endpoint()`; it never resolves or authorizes on its own.
12. `verification.lab_verification.run_lab_verification()` is a separate manual-only path that explicitly opts into `pin_lab_url()` for both targets and uses the guarded `probe_lab_target()` transport, diff builder, and evidence writer. It is not called by `run_verification()`, workers, or recon.
13. `intelligence.observation_summary.summarize_observations()` turns one asset's stored observations into an `ObservationSummary` split in two: `text` holds only system-derived scalars (URLs, hashes, counts, status codes, record types, fixed field vocabulary) and `untrusted` holds every string that originated from the target, each wrapped as a labeled `UntrustedText`. Unknown or mapping-valued keys, such as header names, are folded into untrusted items referenced by numeric position, so no target-originated text ever becomes a bare prompt string or a source label. An asset with no observations produces a sensible empty-case summary instead of an error.
14. `intelligence.hypothesis_generation.generate_hypotheses()` is the first live caller of `intelligence.llm_client.generate_completion()`. It loads the asset's observations, builds the summary, passes only `summary.text` as the user prompt plus `summary.untrusted` as marked untrusted context, parses `category: description` lines into `Hypothesis` rows, and `session.add()`/`session.flush()`es them with the hardcoded status `"unverified"`. It never commits, never probes, and lets `LLMClientError` propagate. An empty observation set means no model call and an empty list.
15. `intelligence.prioritization.prioritize_hypotheses()` is a pure, offline sort of already-loaded rows: only rows whose status is exactly `"unverified"` are candidates, ordered by category weight (`access_control`/`idor` first), then newest first, then row id, category, and description. No session, network, LLM, or mutation of its input.

## Security Boundaries

- Scope checks are deny-by-default; only explicit exact or wildcard entries authorize hostnames.
- Excluded patterns always win, including when a broader wildcard is authorized.
- New hostname resolution should go through `gateway.resolver.authorized_resolve()`, not call `gateway.dns_pin` directly.
- `verification.http_probe` uses a per-probe Requests adapter to connect to a `pin_url()`-validated address while preserving the hostname for the HTTP Host header and TLS server name. Any future HTTP client must preserve this invariant; resolving the URL again in the client would reintroduce DNS rebinding risk.
- `verification.http_probe.probe_lab_target()` is the only supported lab transport and it is guarded: it rejects the request unless the caller passes `allow_private_network=True` and the target is lab-marked (`is_lab_target=True`, produced only by `pin_lab_url()`). `PinnedTarget.is_lab_target` defaults to `False`, so a public target can never satisfy the guard. It reuses `probe_endpoint()`'s pinned transport, keeping the Host/TLS/pinned-IP invariant in one module; `probe_endpoint()` remains the public-only entry point.
- Probe evidence omits `Set-Cookie`, `Authorization`, `Proxy-Authorization`, and `WWW-Authenticate`; header values are truncated, and only the content-coded body hash and byte count are returned. Response decompression is disabled to keep the hash/length aligned with the body bytes represented by `Content-Length` when present.
- The deterministic diff layer has no vulnerability, severity, or likelihood conclusions. Extra request headers are used for the probe only and are never copied into comparison evidence.
- `Observation.hypothesis_id` is nullable so passive recon evidence can exist independently; verification evidence is linked to a hypothesis and inherits its asset ID from that hypothesis.
- `gateway.lab_mode.pin_lab_url()` is a standalone manual lab-only escape hatch. It requires the explicit `allow_private_network=True` argument, still enforces URL authorization, and returns a `LabPinnedTarget` marked `is_lab_target=True`. Normal workers and verification modules must not import it.
- Target-originated text never reaches the trusted `ObservationSummary.text` or its source labels. Labels use a fixed vocabulary plus numeric positions, and an unrecognized observation type is treated as fully untrusted (conservative default), which keeps prompt-injection content inside `UntrustedText` items instead of in model instructions.
- Generated hypotheses are suggestions for a human reviewer. `generate_hypotheses()` writes only the hardcoded `"unverified"` status, and the parser drops any `status`, `severity`, `confidence`, or `verified` line, so model output cannot promote its own claims. `prioritization` is fail-closed in the same spirit: anything not exactly `"unverified"` is excluded from ranking.
- Recon is passive DNS only. The HTTP probe is a single explicit request and does not follow redirects. No port scanning or autonomous actions are part of V1.
- `programs/example_program.yaml` uses `.test`, a reserved testing domain; it is not a live target configuration.

## Validation

Run the suite with the project environment:

```sh
python -m pytest -q
```

The V1 end-to-end test mocks the pinning and DNS boundaries and uses in-memory SQLite. Before live use, a human must review `gateway/dns_pin.py` and configure only program-authorized domains.

## Intelligence API Configuration

`intelligence.llm_client` is API-only DeepSeek infrastructure and has exactly one caller in an investigation flow: `intelligence.hypothesis_generation.generate_hypotheses()`. It reads `DEEPSEEK_API_KEY` from the process environment; no other module imports it, and nothing calls it at import time, on a schedule, or in a loop. Provide the key through a local secret manager or environment configuration; never commit the key to this repository. Tokens are spent only when an operator deliberately runs generation, or by tests that mock the transport.
