#!/usr/bin/env python3
"""Manual, lab-only cross-account basket-access experiment for local Juice Shop.

This is a *manual* operator script, deliberately kept out of the automated test
suite and the normal workers. It is the documented way to exercise the guarded
lab transport (``run_lab_verification``) end to end against a local, deliberately
vulnerable OWASP Juice Shop instance.

Properties enforced here:
  * Local lab only: the base URL is hard-coded to ``http://127.0.0.1:3000``.
  * Authorization is an exact allowlist of the single endpoint under test
    (``/rest/basket/<A-or-B-id>``); no other URL can be pinned or probed.
  * ``allow_private_network=True`` is required for every lab probe.
  * Setup fails closed (``validate_setup_controls``) *before* any evidence exists:
    both basket reads must return HTTP 200, A's basket must contain the seeded
    product, and B's basket must be empty and distinguishable from A's. Broken
    controls abort the run instead of producing meaningless evidence.
  * Account credentials and JWTs stay in memory. They are never printed,
    persisted, or attached to evidence.
  * Evidence is written to a *separate* lab database (``lab_evidence.db``), never
    the investigation database. The hypothesis status is never changed.
  * The lab transaction is committed only after both comparisons succeed *and*
    the hypothesis is re-asserted to still be ``unverified``.

The script itself is manual and is never executed by the automated test suite;
only its pure fail-closed gates are unit-tested
(``tests/test_lab_basket_access_experiment.py``).

Usage:
    venv/bin/python scripts/lab_basket_access_experiment.py
"""

from __future__ import annotations

import hashlib
import secrets
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from data.db import init_db  # noqa: E402
from data.models import Asset, Hypothesis, Investigation, Program  # noqa: E402
from verification.lab_verification import run_lab_verification  # noqa: E402
from verification.run_verification import VerificationRunResult  # noqa: E402

BASE_URL = "http://127.0.0.1:3000"
LAB_DB_URL = f"sqlite+pysqlite:///{REPO_ROOT / 'lab_evidence.db'}"
PRODUCT_ID = 1
HTTP_TIMEOUT = 10.0


@dataclass(frozen=True)
class BasketRead:
    """Setup-only view of one basket read made with the plain (non-probe) client."""

    status_code: int
    content_length: int
    body_sha256: str
    product_ids: frozenset[int]


def _first_record(payload: Any) -> dict[str, Any]:
    """Accept both ``[...]`` and ``{"data": [...]}`` shapes from a lab target."""
    records = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(records, list) or not records:
        raise RuntimeError("unexpected list payload from the lab target")
    record = records[0]
    if not isinstance(record, dict):
        raise RuntimeError("unexpected record shape from the lab target")
    return record


def parse_product_ids(payload: Any) -> frozenset[int]:
    """Extract the product ids from a ``/rest/basket/<id>`` payload.

    Accepts the documented Juice Shop envelope (``{"data": {"Products": [...]}}``)
    plus bare ``{"Products": [...]}`` and ``[...]`` shapes. An unrecognized shape
    raises, because a basket whose contents cannot be read is not a usable control.
    """
    body: Any = payload.get("data", payload) if isinstance(payload, dict) else payload
    if isinstance(body, dict):
        products: Any = body.get("Products", [])
    elif isinstance(body, list):
        products = body
    else:
        raise RuntimeError("unexpected basket payload from the lab target")
    if not isinstance(products, list):
        raise RuntimeError("expected a list of basket products from the lab target")

    ids: set[int] = set()
    for product in products:
        if not isinstance(product, dict):
            continue
        product_id = product.get("id")
        if isinstance(product_id, int) and not isinstance(product_id, bool):
            ids.add(product_id)
    return frozenset(ids)


def validate_setup_controls(
    read_a: BasketRead,
    read_b: BasketRead,
    *,
    product_id: int = PRODUCT_ID,
) -> None:
    """Fail closed unless the two accounts form a usable control pair.

    Both reads must succeed, A's basket must contain the seeded product, and B's
    basket must be empty and distinguishable from A's. Any violation raises while
    the run is still in the pre-evidence setup phase, so a broken control pair can
    never produce evidence.
    """
    if read_a.status_code != 200 or read_b.status_code != 200:
        raise RuntimeError(
            "refusing to run: both basket reads must be HTTP 200 "
            f"(A={read_a.status_code}, B={read_b.status_code})"
        )
    if product_id not in read_a.product_ids:
        raise RuntimeError(
            f"refusing to run: A's basket does not contain seeded product {product_id}"
        )
    if read_b.product_ids:
        raise RuntimeError(
            "refusing to run: B's basket must be empty, but it contains "
            f"{len(read_b.product_ids)} product(s)"
        )
    if read_a.body_sha256 == read_b.body_sha256:
        raise RuntimeError(
            "refusing to run: the two basket responses are byte-identical, so they "
            "cannot act as distinct controls"
        )


def _register_account(client: requests.Session, email: str, password: str) -> None:
    """Create one disposable account using the auto-exposed REST API."""
    questions = client.get(f"{BASE_URL}/api/SecurityQuestions", timeout=HTTP_TIMEOUT)
    questions.raise_for_status()
    first = _first_record(questions.json())
    response = client.post(
        f"{BASE_URL}/api/Users",
        json={
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": first["id"], "question": first["question"]},
            "securityAnswer": secrets.token_hex(8),
        },
        timeout=HTTP_TIMEOUT,
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(f"account registration failed: HTTP {response.status_code}")


def _login(client: requests.Session, email: str, password: str) -> tuple[str, int]:
    """Return ``(jwt, basket_id)`` for one account. The JWT is never logged."""
    response = client.post(
        f"{BASE_URL}/rest/user/login",
        json={"email": email, "password": password},
        timeout=HTTP_TIMEOUT,
    )
    response.raise_for_status()
    authentication = response.json()["authentication"]
    return str(authentication["token"]), int(authentication["bid"])


def _add_basket_item(client: requests.Session, token: str, basket_id: int) -> None:
    """Put one known product into the authenticated account's own basket."""
    response = client.post(
        f"{BASE_URL}/api/BasketItems",
        json={"ProductId": PRODUCT_ID, "BasketId": basket_id, "quantity": 1},
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(f"basket seeding failed: HTTP {response.status_code}")


def _read_basket(client: requests.Session, token: str, basket_id: int) -> BasketRead:
    """Read one basket with a plain client, for setup validation only.

    The body is reduced to a length, a hash, and the product ids; it is never
    printed, persisted, or passed into evidence.
    """
    response = client.get(
        f"{BASE_URL}/rest/basket/{basket_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    body = response.content
    product_ids: frozenset[int] = frozenset()
    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError as error:
            raise RuntimeError(
                "refusing to run: basket read was HTTP 200 but not JSON"
            ) from error
        product_ids = parse_product_ids(payload)
    return BasketRead(
        status_code=response.status_code,
        content_length=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        product_ids=product_ids,
    )


def exact_url_authorizer(allowed_urls: Iterable[str]) -> Callable[[str], bool]:
    """Authorize only the exact basket URLs under test, nothing else."""
    allowed = frozenset(allowed_urls)

    def authorize(url: str) -> bool:
        return url in allowed

    return authorize


def _create_hypothesis(session: Session) -> int:
    program = Program(
        name="Local Juice Shop Lab",
        authorized_scope=["127.0.0.1"],
        excluded_scope=[],
        rate_limit=10,
    )
    investigation = Investigation(program=program, status="running")
    asset = Asset(investigation=investigation, hostname="127.0.0.1")
    hypothesis = Hypothesis(
        asset=asset,
        category="access_control",
        description=(
            "Whether a second account can read a first account's basket by id "
            "on the local lab target."
        ),
    )
    session.add(hypothesis)
    session.flush()
    return hypothesis.id


def load_hypothesis_status(session: Session, hypothesis_id: int) -> str:
    """Return the hypothesis status, failing closed if the row is missing."""
    hypothesis = session.get(Hypothesis, hypothesis_id)
    if hypothesis is None:
        raise RuntimeError(
            f"hypothesis {hypothesis_id} is missing from the lab session"
        )
    return hypothesis.status


def require_unverified(session: Session, hypothesis_id: int, *, stage: str) -> str:
    """Assert the hypothesis is still ``unverified`` before evidence is committed.

    Verification records observations; it never promotes a hypothesis, so a status
    change here means the run is no longer the manual experiment it claims to be.
    """
    status = load_hypothesis_status(session, hypothesis_id)
    if status != "unverified":
        raise RuntimeError(
            f"refusing to continue {stage}: hypothesis {hypothesis_id} is "
            f"'{status}', expected 'unverified'"
        )
    return status


def _report(label: str, result: VerificationRunResult) -> None:
    """Print only status codes, hash-match, lengths, and the evidence id."""
    diff = result.diff
    print(f"  {label}")
    print(f"    url_a={diff.url_a}")
    print(f"    url_b={diff.url_b}")
    print(
        f"    status_a={diff.status_a} status_b={diff.status_b}"
        f" status_match={diff.status_match}"
    )
    print(f"    body_match={diff.body_match}")
    print(
        f"    length_a={diff.probe_a.content_length}"
        f" length_b={diff.probe_b.content_length}"
        f" content_length_delta={diff.content_length_delta}"
    )
    print(f"    evidence_id={result.observation.id}")


def main() -> int:
    if not BASE_URL.startswith("http://127.0.0.1:"):
        raise SystemExit("Refusing to run: this experiment is local-lab only.")

    try:
        requests.get(f"{BASE_URL}/", timeout=HTTP_TIMEOUT)
    except requests.RequestException as error:
        raise SystemExit(
            f"Lab target {BASE_URL} is unreachable ({type(error).__name__}). "
            "Start the local Juice Shop instance first."
        ) from error

    suffix = secrets.token_hex(4)
    email_a = f"lab-a-{suffix}@local.test"
    email_b = f"lab-b-{suffix}@local.test"
    password = "Lab-" + secrets.token_urlsafe(18)

    with requests.Session() as client:
        client.trust_env = False
        _register_account(client, email_a, password)
        _register_account(client, email_b, password)
        token_a, basket_a = _login(client, email_a, password)
        token_b, basket_b = _login(client, email_b, password)
        if basket_a == basket_b:
            raise RuntimeError("expected two distinct lab baskets")
        _add_basket_item(client, token_a, basket_a)

        read_a = _read_basket(client, token_a, basket_a)
        read_b = _read_basket(client, token_b, basket_b)
        print("Setup controls (plain client, body reduced to a hash):")
        print(
            f"  A's own basket:  status={read_a.status_code}"
            f" length={read_a.content_length} sha256={read_a.body_sha256[:12]}"
            f" seeded_product_{PRODUCT_ID}_present={PRODUCT_ID in read_a.product_ids}"
        )
        print(
            f"  B's own basket:  status={read_b.status_code}"
            f" length={read_b.content_length} sha256={read_b.body_sha256[:12]}"
            f" products={len(read_b.product_ids)}"
        )
        print(f"  baskets_differ={read_a.body_sha256 != read_b.body_sha256}")
        # Fail closed here, before any hypothesis or evidence row exists.
        validate_setup_controls(read_a, read_b)

    url_basket_a = f"{BASE_URL}/rest/basket/{basket_a}"
    url_basket_b = f"{BASE_URL}/rest/basket/{basket_b}"
    authorize = exact_url_authorizer({url_basket_a, url_basket_b})
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    engine = init_db(LAB_DB_URL)
    try:
        with Session(engine) as session:
            hypothesis_id = _create_hypothesis(session)
            status_before = require_unverified(session, hypothesis_id, stage="at setup")

            first = run_lab_verification(
                hypothesis_id,
                url_basket_a,
                url_basket_a,
                allow_private_network=True,
                authorize=authorize,
                session=session,
                extra_headers_a=headers_a,
                extra_headers_b=headers_b,
            )
            require_unverified(session, hypothesis_id, stage="after call 1")

            second = run_lab_verification(
                hypothesis_id,
                url_basket_a,
                url_basket_b,
                allow_private_network=True,
                authorize=authorize,
                session=session,
                extra_headers_a=headers_b,
                extra_headers_b=headers_b,
            )

            # Both comparisons succeeded and the hypothesis is still unverified,
            # so the caller-owned transaction may commit.
            require_unverified(session, hypothesis_id, stage="before commit")
            session.commit()

            status_after = load_hypothesis_status(session, hypothesis_id)
            print(f"\nLab evidence ({LAB_DB_URL}):")
            _report("Call 1: A reads A's basket vs. B reads A's basket", first)
            _report("Call 2: B reads A's basket vs. B reads B's basket", second)
            print(
                "\nHypothesis status unchanged:"
                f" {status_before == status_after == 'unverified'}"
                f" (before={status_before} after={status_after})"
            )
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
