"""Tests for the offline endpoint inventory.

Both functions are pure over a string and a callback, so the cases here need no
fixtures, no session, and no transport: each is a literal in and a literal out.
The network guarantee is asserted statically, against the module's own source,
because the only way to show a module cannot make a request is to show it has no
client to make one with - a behavioural test would prove only that one call did
not happen to send anything.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

import pytest

from verification.endpoint_inventory import (
    SEED_PATHS,
    inventory_from_seeds,
    seed_paths,
)

REPO_ROOT = Path(__file__).parents[1]
MODULE_PATH = REPO_ROOT / "verification" / "endpoint_inventory.py"

BASE = "http://127.0.0.1:3000"

# The seed set is pinned here as literals so that changing what would be looked
# at is a deliberate, visible edit to a test rather than a quiet edit to a tuple.
EXPECTED_SEED_PATHS = (
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

EXPECTED_URLS = [
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:3000/robots.txt",
    "http://127.0.0.1:3000/api",
    "http://127.0.0.1:3000/rest",
    "http://127.0.0.1:3000/login",
    "http://127.0.0.1:3000/register",
    "http://127.0.0.1:3000/swagger.json",
    "http://127.0.0.1:3000/openapi.json",
    "http://127.0.0.1:3000/.well-known/security.txt",
]


def exact_url_authorizer(allowed: tuple[str, ...]) -> Callable[[str], bool]:
    """The allowlist shape the operator scripts use: exact string match only."""
    allowed_urls = frozenset(allowed)
    return lambda url: url in allowed_urls


# --- the seed list and the join --------------------------------------------


def test_the_seed_paths_are_the_documented_set() -> None:
    assert SEED_PATHS == EXPECTED_SEED_PATHS


def test_seed_paths_joins_every_seed_to_the_base() -> None:
    assert seed_paths(BASE) == EXPECTED_URLS


def test_every_seed_is_absolute_and_has_no_doubled_separator() -> None:
    for url in seed_paths(BASE):
        assert url.startswith("http://127.0.0.1:3000/")
        assert url.count("://") == 1
        assert "//" not in url.split("://", 1)[1]


def test_a_trailing_slash_on_the_base_does_not_change_the_result() -> None:
    assert seed_paths(BASE + "/") == EXPECTED_URLS
    assert seed_paths(BASE + "//") == EXPECTED_URLS


def test_a_base_path_is_kept_as_a_prefix() -> None:
    urls = seed_paths("https://example.com/app")

    assert len(urls) == len(EXPECTED_SEED_PATHS)
    assert urls[0] == "https://example.com/app/"
    assert "https://example.com/app/robots.txt" in urls
    assert all(url.startswith("https://example.com/app/") for url in urls)


def test_the_scheme_is_lowercased_and_the_host_is_left_as_written() -> None:
    urls = seed_paths("HTTP://Example.com")

    assert urls[0] == "http://Example.com/"
    assert all(url.startswith("http://Example.com/") for url in urls)


def test_seed_paths_returns_a_fresh_list_every_call() -> None:
    first = seed_paths(BASE)
    first.append("http://127.0.0.1:3000/injected")

    assert seed_paths(BASE) == EXPECTED_URLS


# --- fail-closed base validation -------------------------------------------


@pytest.mark.parametrize(
    "bad_base",
    [
        "ftp://example.com",
        "file:///etc/passwd",
        "ws://example.com",
        "gopher://example.com",
        "javascript:alert(1)",
        "//example.com",
        "example.com:3000",
        "127.0.0.1:3000",
        "",
        "   ",
    ],
)
def test_seed_paths_rejects_a_base_that_is_not_http_or_https(bad_base: str) -> None:
    with pytest.raises(ValueError):
        seed_paths(bad_base)


@pytest.mark.parametrize("bad_base", [None, 3000, b"http://example.com"])
def test_seed_paths_rejects_a_non_string_base(bad_base: object) -> None:
    with pytest.raises(ValueError):
        seed_paths(bad_base)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_base", ["http://", "http:///rest", "https:///"])
def test_seed_paths_rejects_a_base_without_a_host(bad_base: str) -> None:
    with pytest.raises(ValueError):
        seed_paths(bad_base)


@pytest.mark.parametrize(
    "bad_base",
    [
        "https://example.com/?a=1",
        "https://example.com/#fragment",
        "https://e.com/p?q=1",
    ],
)
def test_seed_paths_rejects_a_query_or_fragment_rather_than_dropping_it(
    bad_base: str,
) -> None:
    with pytest.raises(ValueError):
        seed_paths(bad_base)


@pytest.mark.parametrize(
    "bad_base",
    [
        "http://user:pass@example.com",
        "https://user@example.com",
        "http://user:pass@127.0.0.1:3000",
        "http://:pass@example.com",
        "https://user:pass@example.com/rest",
        "http://user:pass@example.com/?a=1",
    ],
)
def test_seed_paths_rejects_a_base_that_carries_userinfo(bad_base: str) -> None:
    """A credential in the authority must fail closed, not be copied onward."""
    with pytest.raises(ValueError):
        seed_paths(bad_base)


def test_userinfo_is_rejected_before_the_callback_is_consulted() -> None:
    """Fail closed at normalization: no candidate, and no authorization call."""
    seen: list[str] = []

    def authorize(url: str) -> bool:
        seen.append(url)
        return True

    with pytest.raises(ValueError):
        inventory_from_seeds("http://user:pass@example.com", authorize)

    assert seen == []


def test_an_at_sign_in_the_path_is_not_mistaken_for_userinfo() -> None:
    """An ``@`` after the first ``/`` is a path character, not a credential."""
    urls = seed_paths("http://example.com/a@b")

    assert urls[0] == "http://example.com/a@b/"
    assert urls[1] == "http://example.com/a@b/robots.txt"


def test_no_candidate_ever_carries_userinfo() -> None:
    """The authority of every candidate is bare host[:port]."""

    def authority(url: str) -> str:
        return url.split("/", 3)[2]

    for base in ("http://example.com", "http://example.com/a@b", "https://e.com/x"):
        for url in seed_paths(base):
            assert "@" not in authority(url)



# --- the authorized inventory ----------------------------------------------


def test_inventory_keeps_only_the_urls_the_callback_approved() -> None:
    authorize = exact_url_authorizer((BASE + "/", BASE + "/robots.txt"))

    assert inventory_from_seeds(BASE, authorize) == [
        "http://127.0.0.1:3000/",
        "http://127.0.0.1:3000/robots.txt",
    ]


def test_inventory_is_empty_when_the_callback_rejects_everything() -> None:
    seen: list[str] = []

    def authorize(url: str) -> bool:
        seen.append(url)
        return False

    assert inventory_from_seeds(BASE, authorize) == []
    assert seen == EXPECTED_URLS


def test_inventory_offers_every_candidate_and_keeps_seed_order() -> None:
    allowlist = exact_url_authorizer((BASE + "/rest", BASE + "/api"))
    seen: list[str] = []

    def authorize(url: str) -> bool:
        seen.append(url)
        return allowlist(url)

    result = inventory_from_seeds(BASE, authorize)

    assert seen == EXPECTED_URLS
    assert result == ["http://127.0.0.1:3000/api", "http://127.0.0.1:3000/rest"]


def test_inventory_never_invents_a_url_the_callback_did_not_see() -> None:
    assert inventory_from_seeds(BASE, lambda url: True) == EXPECTED_URLS


def test_inventory_passes_absolute_urls_never_bare_paths() -> None:
    seen: list[str] = []

    def authorize(url: str) -> bool:
        seen.append(url)
        return True

    inventory_from_seeds(BASE, authorize)

    assert all(url.startswith("http://127.0.0.1:3000/") for url in seen)
    assert set(seen) == set(EXPECTED_URLS)


@pytest.mark.parametrize("bad_base", ["ftp://example.com", "", "http:///rest"])
def test_inventory_validates_the_base_before_asking_the_callback(
    bad_base: str,
) -> None:
    calls: list[str] = []

    def authorize(url: str) -> bool:
        calls.append(url)
        return True

    with pytest.raises(ValueError):
        inventory_from_seeds(bad_base, authorize)

    assert calls == []


# --- purity guards ---------------------------------------------------------

ALLOWED_IMPORTS = {"__future__", "collections.abc", "urllib.parse"}


def test_the_module_is_pure_offline_and_has_no_client_to_probe_with() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    for forbidden in (
        "import requests",
        "import socket",
        "urlopen",
        "http_probe",
        "probe_endpoint",
        "probe_lab_target",
        "diff_check",
        # Import-shaped checks only: the module docstring may *name* the pinning
        # gate to explain that authorization is delegated to the caller, but it
        # must never import it (the AST allowlist below is the backstop for that).
        "from gateway",
        "import dns",
        "import urllib.request",
        "sqlalchemy",
        "Session",
        ".commit(",
        ".add(",
        "llm_client",
        "generate_completion",
        "promote_to_finding(",
        "datetime.now",
        "os.environ",
        "open(",
    ):
        assert (
            forbidden not in source
        ), f"endpoint_inventory.py must not contain {forbidden}"

    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    unexpected = imported - ALLOWED_IMPORTS
    assert unexpected == set(), f"unexpected import(s): {unexpected}"

    assert "def seed_paths(" in source
    assert "def inventory_from_seeds(" in source


def test_the_module_exposes_exactly_these_functions() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    functions = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    assert functions == ["_normalized_base", "seed_paths", "inventory_from_seeds"]
