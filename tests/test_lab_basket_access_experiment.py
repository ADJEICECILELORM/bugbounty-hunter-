"""Unit tests for the manual lab experiment's fail-closed gates.

The experiment script itself is manual and is never executed by this suite. These
tests cover only its pure gates, which must refuse to proceed when the setup
controls are wrong, when the target cannot be read, or when the hypothesis status
would change.
"""

import pytest
from sqlalchemy.orm import Session

from data.db import init_db
from data.models import Asset, Hypothesis, Investigation, Program
from scripts import lab_basket_access_experiment as experiment
from scripts.lab_basket_access_experiment import (
    PRODUCT_ID,
    BasketRead,
    exact_url_authorizer,
    load_hypothesis_status,
    parse_product_ids,
    require_unverified,
    validate_setup_controls,
)


def _read(
    *,
    status_code: int = 200,
    body_sha256: str = "a" * 64,
    product_ids: frozenset[int] = frozenset(),
    content_length: int = 100,
) -> BasketRead:
    return BasketRead(
        status_code=status_code,
        content_length=content_length,
        body_sha256=body_sha256,
        product_ids=product_ids,
    )


def test_setup_controls_accept_seeded_a_and_empty_b() -> None:
    validate_setup_controls(
        _read(product_ids=frozenset({PRODUCT_ID})),
        _read(body_sha256="b" * 64),
    )


@pytest.mark.parametrize("status_a,status_b", [(500, 200), (403, 200), (200, 403), (200, 404)])
def test_setup_controls_refuse_non_200_basket_reads(status_a: int, status_b: int) -> None:
    with pytest.raises(RuntimeError, match="both basket reads must be HTTP 200"):
        validate_setup_controls(
            _read(status_code=status_a, product_ids=frozenset({PRODUCT_ID})),
            _read(status_code=status_b, body_sha256="b" * 64),
        )


def test_setup_controls_refuse_a_basket_without_the_seeded_product() -> None:
    with pytest.raises(RuntimeError, match="A's basket does not contain seeded product"):
        validate_setup_controls(_read(), _read(body_sha256="b" * 64))


def test_setup_controls_refuse_a_non_empty_b_basket() -> None:
    with pytest.raises(RuntimeError, match="B's basket must be empty"):
        validate_setup_controls(
            _read(product_ids=frozenset({PRODUCT_ID})),
            _read(body_sha256="b" * 64, product_ids=frozenset({2, 3})),
        )


def test_setup_controls_refuse_byte_identical_baskets() -> None:
    with pytest.raises(RuntimeError, match="byte-identical"):
        validate_setup_controls(
            _read(product_ids=frozenset({PRODUCT_ID})),
            _read(),
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"data": {"Products": [{"id": PRODUCT_ID}, {"id": 2}]}},
        {"Products": [{"id": PRODUCT_ID}]},
        [{"id": PRODUCT_ID}],
        {"data": [{"id": PRODUCT_ID}]},
    ],
)
def test_parse_product_ids_accepts_the_supported_basket_shapes(payload: object) -> None:
    assert PRODUCT_ID in parse_product_ids(payload)


def test_parse_product_ids_returns_empty_for_an_empty_basket() -> None:
    assert parse_product_ids({"data": {"Products": []}}) == frozenset()


@pytest.mark.parametrize(
    "payload",
    [
        {"data": {}},
        {"data": {"Products": "not-a-list"}},
        {"data": {"Products": [{"id": "1"}]}},
        {"data": {"Products": [{"name": "missing id"}]}},
        {"data": {"Products": [{"id": True}]}},
        {"data": {"Products": ["not a product object"]}},
        {"data": 7},
        None,
        "text",
    ],
)
def test_parse_product_ids_refuses_unreadable_payloads(payload: object) -> None:
    with pytest.raises(RuntimeError):
        parse_product_ids(payload)


def test_exact_url_authorizer_allows_only_the_listed_urls() -> None:
    allowed = "http://127.0.0.1:3000/rest/basket/1"
    authorize = exact_url_authorizer([allowed])

    assert authorize(allowed) is True
    assert authorize("http://127.0.0.1:3000/rest/basket/2") is False
    assert authorize("http://127.0.0.1:3000/") is False
    assert authorize("http://127.0.0.1:3001/rest/basket/1") is False
    assert authorize(f"{allowed}#fragment") is False


def test_exact_url_authorizer_allows_nothing_when_the_allowlist_is_empty() -> None:
    authorize = exact_url_authorizer([])

    assert authorize("http://127.0.0.1:3000/rest/basket/1") is False
    assert authorize("") is False


def _create_hypothesis(session: Session, *, status: str = "unverified") -> Hypothesis:
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
        description="Local lab basket-access control.",
        status=status,
    )
    session.add(hypothesis)
    session.flush()
    return hypothesis


def test_require_unverified_passes_for_a_fresh_hypothesis() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as session:
        hypothesis = _create_hypothesis(session)

        assert load_hypothesis_status(session, hypothesis.id) == "unverified"
        assert require_unverified(session, hypothesis.id, stage="at setup") == "unverified"

    engine.dispose()


def test_require_unverified_refuses_a_promoted_hypothesis() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as session:
        hypothesis = _create_hypothesis(session, status="verified")

        with pytest.raises(RuntimeError, match="expected 'unverified'"):
            require_unverified(session, hypothesis.id, stage="before commit")

    engine.dispose()


def test_require_unverified_sees_an_unflushed_status_change() -> None:
    """The gate runs before ``commit()``, so it must catch in-session drift."""
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as session:
        hypothesis = _create_hypothesis(session)
        hypothesis.status = "verified"
        session.flush()

        with pytest.raises(RuntimeError, match="before commit"):
            require_unverified(session, hypothesis.id, stage="before commit")

        session.rollback()

    engine.dispose()


def test_require_unverified_fails_closed_when_the_hypothesis_is_missing() -> None:
    engine = init_db("sqlite+pysqlite:///:memory:")
    with Session(engine) as session:
        with pytest.raises(RuntimeError, match="missing from the lab session"):
            require_unverified(session, 999, stage="before commit")

    engine.dispose()


def _stub_lab_transport(
    monkeypatch: pytest.MonkeyPatch,
    read_a: BasketRead,
    read_b: BasketRead,
) -> list[str]:
    """Replace every side-effecting step of ``main()`` and record what runs."""
    events: list[str] = []
    reads = iter([read_a, read_b])
    logins = [("token-a", 101), ("token-b", 202)]

    class _FakeClient:
        trust_env = True

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, *_exc: object) -> bool:
            return False

    class _FakeRequests:
        RequestException = RuntimeError

        @staticmethod
        def get(*_args: object, **_kwargs: object) -> object:
            return object()

        @staticmethod
        def Session() -> "_FakeClient":  # noqa: N802 - mirrors the requests API
            return _FakeClient()

    def fake_init_db(*_args: object, **_kwargs: object) -> object:
        events.append("init_db")
        return object()

    def fake_run_lab_verification(*_args: object, **_kwargs: object) -> object:
        events.append("run_lab_verification")
        return object()

    monkeypatch.setattr(experiment, "requests", _FakeRequests)
    monkeypatch.setattr(experiment, "_register_account", lambda *_a, **_k: None)
    monkeypatch.setattr(experiment, "_login", lambda *_a, **_k: logins.pop(0))
    monkeypatch.setattr(experiment, "_add_basket_item", lambda *_a, **_k: None)
    monkeypatch.setattr(experiment, "_read_basket", lambda *_a, **_k: next(reads))
    monkeypatch.setattr(experiment, "init_db", fake_init_db)
    monkeypatch.setattr(experiment, "run_lab_verification", fake_run_lab_verification)
    return events


def test_main_creates_no_evidence_when_the_setup_controls_are_wrong(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events = _stub_lab_transport(
        monkeypatch,
        _read(product_ids=frozenset({PRODUCT_ID})),
        _read(body_sha256="b" * 64, product_ids=frozenset({7})),
    )

    with pytest.raises(RuntimeError, match="B's basket must be empty"):
        experiment.main()

    assert events == []
    assert "products=1" in capsys.readouterr().out


def test_main_creates_no_evidence_when_a_basket_read_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _stub_lab_transport(
        monkeypatch,
        _read(status_code=500, product_ids=frozenset({PRODUCT_ID})),
        _read(body_sha256="b" * 64, status_code=403),
    )

    with pytest.raises(RuntimeError, match="both basket reads must be HTTP 200"):
        experiment.main()

    assert events == []
