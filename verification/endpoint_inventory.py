"""The candidate endpoint list for one base URL - pure, offline, no requests.

The inventory step answers one narrow question: *given a base URL, which of a
fixed set of common paths would policy let us look at?* This slice answers only
that question. Both functions are pure over a string and a caller-supplied
authorization callback:

* no request is made and no HTTP client is imported, so it cannot probe;
* no session or database is opened, so it cannot store or promote anything;
* no model is called, so nothing suggested here can become evidence;
* scope is **not** decided here. Authorization is delegated to the ``authorize``
  callback, the same ``Callable[[str], bool]`` shape ``gateway.dns_pin`` uses for
  its ``URLAuthorizer``, so the real gate (or a lab allowlist, or a test double)
  answers for every candidate URL and this module cannot widen scope on its own.

What is deliberately absent matters as much as what is present: nothing here
resolves a name, follows a link, reads a wordlist, or turns an allowed candidate
into a request. An inventory is the *input* to a later, explicitly authorized
probe, never a scan - the seed list is short, fixed, and public so a reviewer can
read the entire plan before anything is authorized.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

# A short, fixed list of paths a typical web application exposes. Hard-coded on
# purpose: a generated or model-suggested seed list would not be auditable, and
# the whole point of this slice is that a human can read the plan in full.
SEED_PATHS: tuple[str, ...] = (
    "/",
    "/robots.txt",
    "/api",
    "/rest",
    "/login",
    "/register",
    "/swagger.json",
    "/openapi.json",
    "/.well-known/security.txt",
)

_ALLOWED_SCHEMES = ("http", "https")


def _normalized_base(base_url: str) -> str:
    """Return the origin plus path prefix that the seed paths hang off.

    Fail-closed: a base that is not an absolute ``http``/``https`` URL with a
    host is rejected rather than guessed at, and a query or fragment is rejected
    rather than silently dropped - the caller meant a specific resource, and
    quietly changing which URL gets authorized would be a security-relevant
    surprise. Only trailing slashes are removed, so joining cannot double a
    separator.
    """
    if not isinstance(base_url, str):
        raise ValueError("base_url must be a string")
    parsed = urlsplit(base_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"base_url must be http or https, got {scheme!r}")
    if not parsed.netloc:
        raise ValueError("base_url must include a host")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not carry a query or fragment")
    return urlunsplit((scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def seed_paths(base_url: str) -> list[str]:
    """Join the fixed seed list onto ``base_url`` and return absolute URLs.

    The join is deliberate concatenation of the normalized base and a path that
    starts with ``/``, so ``"/"`` stays a single slash and no candidate is ever
    produced with a doubled separator. The order is the order of
    :data:`SEED_PATHS`, and a fresh list is returned on every call.
    """
    base = _normalized_base(base_url)
    return [f"{base}{path}" for path in SEED_PATHS]


def inventory_from_seeds(
    base_url: str,
    authorize: Callable[[str], bool],
) -> list[str]:
    """Seed candidates filtered by ``authorize``, in seed order.

    Fail-closed: a URL is kept only when the callback answered true for that
    exact string, every candidate is offered to the callback, and nothing is
    returned that the callback did not see. An authorizer that rejects
    everything yields an empty inventory, not a default.
    """
    return [url for url in seed_paths(base_url) if authorize(url)]
