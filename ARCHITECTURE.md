# Architecture

## V1 Scope

V1 provides program configuration, scope enforcement, safe DNS resolution, passive DNS discovery, and relational storage. It does not perform autonomous investigation or active scanning. The current interface is a set of Python modules; there is no CLI or service entry point yet.

## Data Flow

1. `gateway.program_config.load_program()` loads and validates YAML program metadata and scope patterns.
2. `gateway.scope_policy.ScopePolicy` canonicalizes exact and `*.` hostname patterns. Exclusions take precedence over all authorizations.
3. `gateway.resolver.authorized_resolve()` rejects out-of-scope hostnames before delegating to `gateway.dns_pin.pin_url()`. The pinning layer validates the URL, authorizes it again, resolves it, and rejects any non-public answer. The adapter returns one validated IP.
4. `workers.recon.passive_discover()` calls the authorized resolver before querying A, AAAA, MX, and TXT records through dnspython. It performs DNS lookups only.
5. `workers.storage.store_observations()` creates or reuses an asset within an investigation and adds observations to the caller's SQLAlchemy session. The caller owns commit and rollback.
6. `data.models` defines Program, Investigation, Asset, and Observation. `data.db.init_db()` creates the schema and returns an engine.

## Security Boundaries

- Scope checks are deny-by-default; only explicit exact or wildcard entries authorize hostnames.
- Excluded patterns always win, including when a broader wildcard is authorized.
- New hostname resolution should go through `gateway.resolver.authorized_resolve()`, not call `gateway.dns_pin` directly.
- `pin_url()` returns the validated destination addresses. Any future HTTP client must connect to one of those pinned addresses while preserving the hostname for the HTTP Host header and TLS server name; resolving the URL again in the client would reintroduce DNS rebinding risk.
- Recon is passive DNS only. No port scanning, HTTP probing, or autonomous actions are part of V1.
- `programs/example_program.yaml` uses `.test`, a reserved testing domain; it is not a live target configuration.

## Validation

Run the suite with the project environment:

```sh
python -m pytest -q
```

The V1 end-to-end test mocks the pinning and DNS boundaries and uses in-memory SQLite. Before live use, a human must review `gateway/dns_pin.py` and configure only program-authorized domains.
