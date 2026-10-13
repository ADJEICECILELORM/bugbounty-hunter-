#!/usr/bin/env python3
"""Operator-only live demonstration of the V3 controlled-verification path.

This is the V3 counterpart of ``scripts/lab_basket_access_experiment.py``. It is
*manual*: nothing imports it, the automated test suite never executes it, and no
worker calls it. It exists to exercise the **new** gated runner
(:func:`verification.run_hypothesis_verification.run_hypothesis_verification`)
end to end against a local, deliberately vulnerable OWASP Juice Shop instance,
and to show the verdicts and integrity digests that come out of it.

What it does, in order:
  1. Creates two *fresh* disposable accounts on every run, and seeds A's basket.
  2. Fails closed (``validate_setup_controls``) *before* any hypothesis or
     evidence row exists: both basket reads must be HTTP 200, A's basket must
     contain the seeded product, B's basket must be empty, and the two recorded
     bodies must differ.
  3. Builds a two-pair ``VerificationTestPlan``: one control pair (different
     URLs, expected to differ) and one claim pair (the same URL read by two
     different identities).
  4. Runs the runner with ``allow_private_network=True`` and an exact-URL
     authorizer covering only the two basket URLs under test, so nothing else in
     the lab can be pinned or probed.
  5. Prints, for each pair: the pair name, the observation id, the verdict and
     its reason codes, the rationale, the first 16 characters of the stored
     ``verdict-integrity-v1`` digest, and whether ``verify_verdict()`` re-derives
     the judgement from the stored evidence.

Properties enforced here:
  * Local lab only: ``BASE_URL`` is hard-coded to ``http://127.0.0.1:3000``.
  * Separate database: evidence goes to ``lab_evidence_v3.db``. The Part 1 record
    in ``lab_evidence.db`` is never opened, and the script refuses to start if it
    is pointed at it.
  * This script owns the transaction. The runner never commits, and it never
    writes ``Hypothesis.status``; the status is asserted ``unverified`` before
    and after the run.
  * No promotion path: ``verification.finding_promotion`` must not be imported
    into this process, so no ``Finding`` row and no approval can be created here.
  * Credentials and JWTs stay in memory. Only status codes, lengths and hashes
    are printed, and no credential field is ever attached to evidence.

The fail-closed gates are *imported* from the Part 1 script rather than copied:
they are unit-tested there (``tests/test_lab_basket_access_experiment.py``), and a
second copy would be a second, untested implementation of the checks that keep a
broken setup from producing evidence.

Usage:
    docker run --rm -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
    venv/bin/python scripts/lab_basket_access_v3.py

If the lab target is down, the script exits with that command instead of
attempting any request. Nothing is submitted anywhere and nothing is approved:
this demonstrates verification, not promotion.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

import requests
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from data.db import init_db  # noqa: E402
from scripts import lab_basket_access_experiment as lab  # noqa: E402
from verification.run_hypothesis_verification import (  # noqa: E402
    HypothesisVerificationResult,
    PairOutcome,
    RequestPair,
    VerificationTestPlan,
    run_hypothesis_verification,
)
from verification.verdict_checker import (  # noqa: E402
    CROSS_ACCOUNT_SAME_BYTES,
    SUPPORTED,
    VerdictClaim,
)
from verification.verdict_integrity import (  # noqa: E402
    DIGEST_SCHEMA,
    verify_verdict,
)

BASE_URL = "http://127.0.0.1:3000"
PRODUCT_ID = lab.PRODUCT_ID
HTTP_TIMEOUT = lab.HTTP_TIMEOUT

# The Part 1 demonstration record and the V3 record are deliberately separate.
PART1_DB_NAME = "lab_evidence.db"
V3_DB_NAME = "lab_evidence_v3.db"
V3_DB_PATH = REPO_ROOT / V3_DB_NAME
LAB_DB_URL = f"sqlite+pysqlite:///{V3_DB_PATH}"

PROBE_TIMEOUT_SECONDS = 10.0
# Deliberately not verdict_integrity.DIGEST_PREFIX_LENGTH (12): this is the
# operator-facing prefix length the demonstration prints.
DIGEST_PREFIX_CHARS = 16


def assert_separate_database() -> None:
    """Refuse to run against the Part 1 evidence database.

    The Part 1 record is a reference artifact: one unverified hypothesis and two
    observations written by the V2 path. Writing V3 rows into it would make the
    two demonstrations impossible to tell apart, so this script writes only
    ``lab_evidence_v3.db`` and stops if that is not what it is pointed at.
    """
    part1 = (REPO_ROOT / PART1_DB_NAME).resolve()
    if V3_DB_PATH.name != V3_DB_NAME or V3_DB_PATH.resolve() == part1:
        raise SystemExit(
            f"Refusing to run: this script writes {V3_DB_NAME} only. The Part 1 "
            f"record in {PART1_DB_NAME} must stay untouched."
        )


def assert_no_promotion_path() -> None:
    """Refuse to run if the promotion gate is loaded in this process.

    Verification records verdicts; approval is a separate human act. If
    ``verification.finding_promotion`` is imported here, this process could
    create a ``Finding`` row, which is exactly what a demonstration of
    verification must not be able to do.
    """
    if "verification.finding_promotion" in sys.modules:
        raise SystemExit(
            "Refusing to run: verification.finding_promotion is imported in this "
            "process, and this demonstration must not be able to promote."
        )


def require_lab_reachable() -> None:
    """Exit with the lab start command unless the local target answers."""
    try:
        requests.get(f"{BASE_URL}/", timeout=HTTP_TIMEOUT)
    except requests.RequestException as error:
        raise SystemExit(
            f"Lab target {BASE_URL} is unreachable ({type(error).__name__}).\n"
            "Start the local lab first (prefix with sudo if your user cannot "
            "reach the Docker socket):\n"
            f"  {lab.LAB_START_COMMAND}\n"
            "Then re-run this script."
        ) from error


def build_plan(
    *,
    url_basket_a: str,
    url_basket_b: str,
    headers_a: dict[str, str],
    headers_b: dict[str, str],
) -> VerificationTestPlan:
    """The Part 1 experiment as a validated V3 plan: one control, one claim.

    The runner enforces these shapes, and they are the whole point of the
    experiment: a control pair must compare two *different* URLs (so it shows the
    two baskets really are distinguishable), and a claim pair must request the
    same URL on both sides with non-empty, different headers (so it really is two
    identities reading one object rather than one identity twice).
    """
    return VerificationTestPlan(
        pairs=(
            RequestPair(
                name="control: B reads A's basket vs B reads B's basket",
                url_a=url_basket_a,
                url_b=url_basket_b,
                claim=VerdictClaim(
                    CROSS_ACCOUNT_SAME_BYTES, control_expected_match=False
                ),
                extra_headers_a=headers_b,
                extra_headers_b=headers_b,
            ),
            RequestPair(
                name="claim: A reads A's basket vs B reads A's basket",
                url_a=url_basket_a,
                url_b=url_basket_a,
                claim=VerdictClaim(CROSS_ACCOUNT_SAME_BYTES),
                extra_headers_a=headers_a,
                extra_headers_b=headers_b,
            ),
        )
    )


def _report_outcome(outcome: PairOutcome, hypothesis_id: int) -> None:
    """Print one pair's evidence id, judgement and re-verified integrity state."""
    observation = outcome.observation
    verdict = outcome.verdict
    check = verify_verdict(verdict, observation, hypothesis_id=hypothesis_id)
    role = "control" if outcome.result.is_control else "claim"
    print(f"  {outcome.pair.name}")
    print(
        f"    role={role} observation_id={observation.id}"
        f" type={observation.observation_type}"
    )
    print(
        f"    outcome={outcome.result.verdict}"
        f" reasons={list(outcome.result.reasons)}"
    )
    print(f"    rationale={outcome.result.rationale}")
    print(
        f"    integrity_digest={verdict.integrity_digest[:DIGEST_PREFIX_CHARS]}..."
        f" ({DIGEST_SCHEMA})"
    )
    print(f"    verify_verdict={'pass' if check.ok else f'FAIL ({check.reason})'}")


def _report(result: HypothesisVerificationResult) -> None:
    """Print the stored verdicts, then re-derive each one from its own evidence."""
    print(
        f"\nV3 verdicts (hypothesis {result.hypothesis_id}, "
        f"evidence in {V3_DB_NAME}):"
    )
    for outcome in result.outcomes:
        _report_outcome(outcome, result.hypothesis_id)

    checks = [
        verify_verdict(
            outcome.verdict, outcome.observation, hypothesis_id=result.hypothesis_id
        )
        for outcome in result.outcomes
    ]
    supported = [
        outcome.pair.name
        for outcome in result.primary_outcomes
        if outcome.result.verdict == SUPPORTED
    ]
    print("\nSummary:")
    print(f"  control pairs: {len(result.control_outcomes)} (never support a claim)")
    print(f"  claim pairs:   {len(result.primary_outcomes)}")
    supported_text = ", ".join(supported) if supported else "none"
    print(f"  claim verdicts supported: {supported_text}")
    print(
        "  every verdict re-derived from its own stored evidence:"
        f" {all(check.ok for check in checks)}"
    )


def main() -> int:
    if not BASE_URL.startswith("http://127.0.0.1:"):
        raise SystemExit("Refusing to run: this demonstration is local-lab only.")
    assert_separate_database()
    assert_no_promotion_path()
    require_lab_reachable()

    # Fresh disposable accounts on every run. The emails, the shared password and
    # both JWTs live in this scope only: none of them is printed, logged, or
    # attached to evidence.
    suffix = secrets.token_hex(4)
    email_a = f"lab-a-{suffix}@local.test"
    email_b = f"lab-b-{suffix}@local.test"
    password = "Lab-" + secrets.token_urlsafe(18)

    with requests.Session() as client:
        client.trust_env = False
        lab._register_account(client, email_a, password)
        lab._register_account(client, email_b, password)
        token_a, basket_a = lab._login(client, email_a, password)
        token_b, basket_b = lab._login(client, email_b, password)
        if basket_a == basket_b:
            raise RuntimeError("expected two distinct lab baskets")
        lab._add_basket_item(client, token_a, basket_a)

        read_a = lab._read_basket(client, token_a, basket_a)
        read_b = lab._read_basket(client, token_b, basket_b)
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
        lab.validate_setup_controls(read_a, read_b)

    url_basket_a = f"{BASE_URL}/rest/basket/{basket_a}"
    url_basket_b = f"{BASE_URL}/rest/basket/{basket_b}"
    authorize = lab.exact_url_authorizer({url_basket_a, url_basket_b})
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    plan = build_plan(
        url_basket_a=url_basket_a,
        url_basket_b=url_basket_b,
        headers_a=headers_a,
        headers_b=headers_b,
    )

    engine = init_db(LAB_DB_URL)
    try:
        with Session(engine) as session:
            hypothesis_id = lab._create_hypothesis(session)
            status_before = lab.require_unverified(
                session, hypothesis_id, stage="at setup"
            )

            result = run_hypothesis_verification(
                hypothesis_id,
                plan,
                allow_private_network=True,
                authorize=authorize,
                session=session,
                timeout_seconds=PROBE_TIMEOUT_SECONDS,
            )

            # The runner wrote evidence and verdicts, but it never committed and
            # never touched a status: this script owns the transaction.
            lab.require_unverified(session, hypothesis_id, stage="after the run")
            session.commit()

            status_after = lab.load_hypothesis_status(session, hypothesis_id)
            _report(result)
            print(
                "\nHypothesis status unchanged:"
                f" {status_before == status_after == 'unverified'}"
                f" (before={status_before} after={status_after})"
            )
            print(
                "No promotion was attempted and no Finding row was created: this "
                "run demonstrates verification, not approval."
            )
        return 0
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
