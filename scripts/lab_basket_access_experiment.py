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
  * Account credentials and JWTs stay in memory. They are never printed,
    persisted, or attached to evidence.
  * Evidence is written to a *separate* lab database (``lab_evidence.db``), never
    the investigation database. The hypothesis status is never changed.
  * The lab transaction is committed only after both comparisons succeed.

Usage:
    venv/bin/python scripts/lab_basket_access_experiment.py
"""

from __future__ import annotations

import hashlib
import secrets
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

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


def _first_record(payload: object) -> dict[str, object]:
    """Accept both ``[...]`` and ``{"data": [...]}`` shapes from a lab target."""
    records = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(records, list) or not records:
        raise RuntimeError("unexpected list payload from the lab target")
    record = records[0]
    if not isinstance(record, dict):
        raise RuntimeError("unexpected record shape from the lab target")
    return record


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


def _fingerprint(
    client: requests.Session, token: str, basket_id: int
) -> tuple[int, int, str]:
    """Return ``(status, length, sha256)`` for one basket. The body is discarded."""
    response = client.get(
        f"{BASE_URL}/rest/basket/{basket_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=HTTP_TIMEOUT,
    )
    body = response.content
    return response.status_code, len(body), hashlib.sha256(body).hexdigest()


def _exact_url_authorizer(allowed_urls: Iterable[str]) -> Callable[[str], bool]:
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

        status_a, length_a, hash_a = _fingerprint(client, token_a, basket_a)
        status_b, length_b, hash_b = _fingerprint(client, token_b, basket_b)
        print("Setup validation (plain client, body discarded):")
        print(f"  A's own basket:  status={status_a} length={length_a} sha256={hash_a[:12]}")
        print(f"  B's own basket:  status={status_b} length={length_b} sha256={hash_b[:12]}")
        print(f"  baskets_differ={hash_a != hash_b}")

    url_basket_a = f"{BASE_URL}/rest/basket/{basket_a}"
    url_basket_b = f"{BASE_URL}/rest/basket/{basket_b}"
    authorize = _exact_url_authorizer({url_basket_a, url_basket_b})
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    engine = init_db(LAB_DB_URL)
    try:
        with Session(engine) as session:
            hypothesis_id = _create_hypothesis(session)
            status_before = session.get(Hypothesis, hypothesis_id).status

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

            # Both comparisons succeeded, so the caller-owned transaction commits.
            session.commit()

            status_after = session.get(Hypothesis, hypothesis_id).status
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
