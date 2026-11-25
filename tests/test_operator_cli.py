"""Operator CLI integration tests using isolated temporary SQLite databases."""

from __future__ import annotations

import json
import sqlite3
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

import orchestration.task_runner as task_runner
import scripts.collect_inventory as collect_inventory
import scripts.investigation_status as investigation_status
import scripts.recover_investigation as recover_investigation
import scripts.run_investigation_step as run_investigation_step
import scripts.run_supervised_investigation as run_supervised_investigation
from data.db import create_database_engine, initialize_fresh_database
from data.models import (
    Asset,
    Hypothesis,
    Investigation,
    Observation,
    Program,
    Task,
    TaskEvent,
)
from verification.investigation_lifecycle import start_investigation
from verification.investigation_tasks import create_task


@pytest.fixture()
def operator_db(tmp_path: Path) -> tuple[Path, int, int]:
    path = tmp_path / "operator evidence.sqlite"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    initialize_fresh_database(engine)
    with Session(engine) as session:
        program = Program(
            name="CLI test program",
            authorized_scope=["*.example.test"],
            excluded_scope=["blocked.example.test"],
            rate_limit=2,
        )
        session.add(program)
        session.flush()
        investigation = start_investigation(program.id, session)
        asset = Asset(
            investigation_id=investigation.id, hostname="api.example.test"
        )
        session.add(asset)
        session.flush()
        recon = create_task(
            investigation.id, session, kind="recon", title="Passive recon"
        )
        session.commit()
        result = (path, investigation.id, recon.id)
    engine.dispose()
    return result


def _snapshot(path: Path) -> tuple[bytes, list[tuple[int, str, str]]]:
    data = path.read_bytes()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        tasks = [
            (task.id, task.kind, task.status)
            for task in session.scalars(select(Task).order_by(Task.id))
        ]
    engine.dispose()
    return data, tasks


def test_supervised_dry_run_is_repeatable_and_does_not_write(
    operator_db: tuple[Path, int, int], capsys: pytest.CaptureFixture[str]
) -> None:
    path, investigation_id, task_id = operator_db
    before = _snapshot(path)

    for _ in range(2):
        assert run_supervised_investigation.main(
            [str(investigation_id), "--database", str(path)]
        ) == 0
        assert "Dry run: nothing executed and nothing written" in capsys.readouterr().out
        assert _snapshot(path) == before


def test_supervised_cli_executes_with_custom_database_and_mocked_recon(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, task_id = operator_db
    calls: list[str] = []

    def fake_discover(hostname, policy, limiter):
        calls.append(hostname)
        return []

    monkeypatch.setattr(task_runner, "passive_discover", fake_discover)
    assert run_supervised_investigation.main(
        [str(investigation_id), "--yes", "--database", str(path)]
    ) == 0
    assert calls == ["api.example.test"]
    assert "recon: ok" in capsys.readouterr().out

    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        task = session.get(Task, task_id)
        events = session.scalars(
            select(TaskEvent).where(TaskEvent.task_id == task_id)
        ).all()
        assert task is not None and task.status == "completed"
        assert [event.event_type for event in events] == [
            "created",
            "started",
            "dispatched",
            "completed",
        ]
    engine.dispose()


def test_one_step_cli_executes_custom_database_once(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, task_id = operator_db
    calls: list[str] = []
    monkeypatch.setattr(
        task_runner,
        "passive_discover",
        lambda hostname, policy, limiter: calls.append(hostname) or [],
    )

    assert run_investigation_step.main(
        [str(investigation_id), "--yes", "--database", str(path)]
    ) == 0
    assert calls == ["api.example.test"]
    assert "Done (one pass; no re-dispatch)." in capsys.readouterr().out
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert session.get(Task, task_id).status == "completed"
    engine.dispose()


@pytest.mark.parametrize(
    "base_url",
    [
        "https://user:secret@example.test/",
        "https://api.example.test/?token=secret",
        "https://api.example.test/#secret",
        "https://api.example.test:invalid/",
    ],
)
def test_inventory_cli_rejects_sensitive_or_malformed_base_before_writing(
    operator_db: tuple[Path, int, int], base_url: str
) -> None:
    path, investigation_id, _ = operator_db
    before = path.read_bytes()

    with pytest.raises(SystemExit) as error:
        collect_inventory.main(
            [
                "--investigation",
                str(investigation_id),
                "--base-url",
                base_url,
                "--database",
                str(path),
            ]
        )

    assert "secret" not in str(error.value)
    assert path.read_bytes() == before


def test_inventory_cli_rejects_out_of_scope_host_before_asset_or_task_creation(
    operator_db: tuple[Path, int, int],
) -> None:
    path, investigation_id, _ = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        asset_count_before = len(session.scalars(select(Asset)).all())
        task_count_before = len(session.scalars(select(Task)).all())
    engine.dispose()

    with pytest.raises(SystemExit, match="outside the authorized scope"):
        collect_inventory.main(
            [
                "--investigation",
                str(investigation_id),
                "--base-url",
                "https://outside.invalid/",
                "--database",
                str(path),
            ]
        )

    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert len(session.scalars(select(Asset)).all()) == asset_count_before
        assert len(session.scalars(select(Task)).all()) == task_count_before
    engine.dispose()


def test_inventory_budget_failure_rolls_back_speculative_asset(
    operator_db: tuple[Path, int, int], capsys: pytest.CaptureFixture[str]
) -> None:
    path, investigation_id, _ = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        investigation = session.get(Investigation, investigation_id)
        investigation.max_tasks = 1
        assets_before = len(session.scalars(select(Asset)).all())
        session.commit()
    engine.dispose()

    assert collect_inventory.main(
        [
            "--investigation",
            str(investigation_id),
            "--base-url",
            "https://new.api.example.test/",
            "--database",
            str(path),
        ]
    ) == 1
    assert "task budget exhausted" in capsys.readouterr().out
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert len(session.scalars(select(Asset)).all()) == assets_before
        assert len(session.scalars(select(Task)).all()) == 1
    engine.dispose()

def test_one_step_cli_returns_failure_for_dispatch_error(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, task_id = operator_db

    def fail_discover(*args):
        raise RuntimeError("controlled one-step failure")

    monkeypatch.setattr(task_runner, "passive_discover", fail_discover)
    assert run_investigation_step.main(
        [str(investigation_id), "--yes", "--database", str(path)]
    ) == 1
    assert "Finished one pass with task failures or refusals." in capsys.readouterr().out
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        task = session.get(Task, task_id)
        assert task.status == "failed"
        assert "controlled one-step failure" in task.result_summary
    engine.dispose()


def test_one_step_cli_returns_failure_for_verification_refusal(
    operator_db: tuple[Path, int, int],
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, _ = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        asset = session.scalar(select(Asset))
        hypothesis = Hypothesis(
            asset_id=asset.id,
            category="access_control_review",
            description="Review access controls",
            status="unverified",
        )
        session.add(hypothesis)
        session.flush()
        task = create_task(
            investigation_id,
            session,
            kind="verification",
            title="Verification requires operator input",
            params={"hypothesis_id": hypothesis.id},
        )
        recon = session.scalar(select(Task).where(Task.kind == "recon"))
        recon.status = "completed"
        task_id = task.id
        session.commit()
    engine.dispose()

    assert run_investigation_step.main(
        [str(investigation_id), "--yes", "--database", str(path)]
    ) == 1
    output = capsys.readouterr().out
    assert "needs an operator-supplied verification_plan" in output
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert session.get(Task, task_id).status == "pending"
    engine.dispose()


def test_lab_flag_does_not_bypass_stored_scope(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, task_id = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        investigation = session.get(Investigation, investigation_id)
        investigation.program.authorized_scope = ["other.example.test"]
        session.commit()
    engine.dispose()
    calls: list[str] = []
    monkeypatch.setattr(
        task_runner,
        "passive_discover",
        lambda hostname, policy, limiter: calls.append(hostname) or [],
    )

    assert run_supervised_investigation.main(
        [str(investigation_id), "--yes", "--lab", "--database", str(path)]
    ) == 1
    capsys.readouterr()
    assert calls == []
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert session.get(Task, task_id).status == "pending"
    engine.dispose()


def test_budget_exhaustion_is_reported_without_partial_planning(
    operator_db: tuple[Path, int, int], capsys: pytest.CaptureFixture[str]
) -> None:
    path, investigation_id, _ = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        investigation = session.get(Investigation, investigation_id)
        investigation.max_tasks = 1
        asset = session.scalar(select(Asset))
        session.add(
            Observation(
                asset_id=asset.id,
                observation_type="endpoint_inventory",
                data={"url": "https://api.example.test/account", "status_code": 200},
            )
        )
        session.commit()
    engine.dispose()

    assert run_supervised_investigation.main(
        [str(investigation_id), "--database", str(path)]
    ) == 0
    output = capsys.readouterr().out
    assert "task budget" in output
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert len(session.scalars(select(Task)).all()) == 1
    engine.dispose()


def test_recovery_cli_retries_then_one_step_runs_only_the_retry(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, original_id = operator_db

    def fail_discover(*args):
        raise RuntimeError("controlled CLI failure")

    monkeypatch.setattr(task_runner, "passive_discover", fail_discover)
    assert run_supervised_investigation.main(
        [str(investigation_id), "--yes", "--database", str(path)]
    ) == 1
    failure_output = capsys.readouterr().out
    assert "controlled CLI failure" in failure_output
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        original = session.get(Task, original_id)
        events = session.scalars(
            select(TaskEvent).where(TaskEvent.task_id == original_id)
        ).all()
        assert original.status == "failed"
        assert "controlled CLI failure" in original.result_summary
        assert "dispatch_failed" in [event.event_type for event in events]
    engine.dispose()

    assert recover_investigation.main(
        [str(investigation_id), "--retry", str(original_id), "--database", str(path)]
    ) == 0
    output = capsys.readouterr().out
    assert "Created retry task" in output

    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        tasks = session.scalars(select(Task).order_by(Task.id)).all()
        retry_id = tasks[-1].id
        assert len(tasks) == 2
        assert tasks[-1].status == "pending"
    engine.dispose()

    monkeypatch.setattr(
        task_runner,
        "passive_discover",
        lambda *_: [
            {"type": "dns_record", "record_type": "A", "value": "203.0.113.10"}
        ],
    )
    assert run_investigation_step.main(
        [str(investigation_id), "--yes", "--database", str(path)]
    ) == 0
    capsys.readouterr()
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert session.get(Task, original_id).status == "failed"
        assert session.get(Task, retry_id).status == "completed"
        assert session.scalar(select(Observation).where(Observation.asset_id == 1)) is not None
        assert len(
            session.scalars(select(Observation).where(Observation.asset_id == 1)).all()
        ) == 1
    engine.dispose()


def test_supervised_cli_failure_prints_recovery_guidance(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, task_id = operator_db

    def fail_discover(*args):
        raise RuntimeError("controlled dispatch failure")

    monkeypatch.setattr(task_runner, "passive_discover", fail_discover)
    assert run_supervised_investigation.main(
        [str(investigation_id), "--yes", "--database", str(path)]
    ) == 1
    output = capsys.readouterr().out
    assert "Stopped: a task failed (stop-on-first-failure policy)." in output
    assert f"--retry {task_id}" in output
    assert "recover_investigation.py" in output


def test_scope_refusal_explains_authorized_and_excluded_scope(
    operator_db: tuple[Path, int, int],
) -> None:
    path, investigation_id, _ = operator_db
    with pytest.raises(SystemExit) as error:
        collect_inventory.main(
            [
                "--investigation",
                str(investigation_id),
                "--base-url",
                "https://outside.invalid/",
                "--database",
                str(path),
            ]
        )
    message = str(error.value)
    assert "outside the authorized scope" in message
    assert "'outside.invalid'" in message
    assert "authorized=" in message
    assert "excluded=" in message


def test_status_cli_flags_budget_exhaustion(
    operator_db: tuple[Path, int, int], capsys: pytest.CaptureFixture[str]
) -> None:
    path, investigation_id, _ = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        investigation = session.get(Investigation, investigation_id)
        investigation.max_tasks = 1  # equals the one seeded recon task
        session.commit()
    engine.dispose()

    assert investigation_status.main(
        ["--investigation", str(investigation_id), "--database", str(path)]
    ) == 0
    output = capsys.readouterr().out
    assert "budget exhausted: tasks" in output



def test_inventory_cli_uses_custom_database_and_commits_owned_task(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "inventory.sqlite"
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    initialize_fresh_database(engine)
    with Session(engine) as session:
        program = Program(
            name="Inventory CLI",
            authorized_scope=["*.example.test"],
            excluded_scope=[],
            rate_limit=1,
        )
        session.add(program)
        session.commit()
        program_id = program.id
    engine.dispose()

    def fake_collect(
        session, *, investigation, base_url, authorize, allow_private_network,
        commit_before_dispatch=False,
    ):
        hostname = "api.example.test"
        asset = Asset(investigation_id=investigation.id, hostname=hostname)
        session.add(asset)
        session.flush()
        task = create_task(
            investigation.id,
            session,
            kind="inventory",
            title=f"Collect endpoint inventory for {base_url}",
            params={"asset_id": asset.id, "base_url": base_url},
        )
        task.status = "completed"
        return investigation, asset, task

    monkeypatch.setattr(collect_inventory, "run_collect_inventory", fake_collect)
    assert collect_inventory.main(
        ["--program", str(program_id), "--base-url", "https://api.example.test/", "--database", str(path)]
    ) == 0
    assert "task #1 inventory -> completed" in capsys.readouterr().out
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert session.scalar(select(Task).where(Task.kind == "inventory")) is not None
    engine.dispose()


def test_inventory_cli_checkpoint_survives_interrupted_collection(
    operator_db: tuple[Path, int, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, investigation_id, _ = operator_db

    class SimulatedProcessExit(BaseException):
        pass

    def interrupted_collection(
        base_url, authorize, *, session, asset_id, allow_private_network=False,
        **kwargs,
    ):
        task = session.scalar(
            select(Task).where(Task.kind == "inventory").order_by(Task.id.desc())
        )
        assert task.status == "running"
        assert [event.event_type for event in task.events] == [
            "created", "started", "dispatched"
        ]
        raise SimulatedProcessExit()

    monkeypatch.setattr(
        task_runner, "collect_seed_inventory", interrupted_collection
    )
    with pytest.raises(SimulatedProcessExit):
        collect_inventory.main(
            [
                "--investigation", str(investigation_id),
                "--base-url", "https://api.example.test/",
                "--database", str(path),
            ]
        )

    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        task = session.scalar(
            select(Task).where(Task.kind == "inventory").order_by(Task.id.desc())
        )
        assert task.status == "running"
        assert [event.event_type for event in task.events] == [
            "created", "started", "dispatched"
        ]
    engine.dispose()

def test_status_cli_custom_database_is_read_only(
    operator_db: tuple[Path, int, int], capsys: pytest.CaptureFixture[str]
) -> None:
    path, investigation_id, _ = operator_db
    before = path.read_bytes()
    assert investigation_status.main(
        ["--investigation", str(investigation_id), "--database", str(path)]
    ) == 0
    assert "Investigation #" in capsys.readouterr().out
    assert path.read_bytes() == before


def test_tampered_database_is_refused_before_any_dispatch(
    operator_db: tuple[Path, int, int],
) -> None:
    path, investigation_id, task_id = operator_db
    # Remove a protection trigger to simulate a tampered/corrupted database.
    with sqlite3.connect(path) as database:
        database.execute("DROP TRIGGER retain_observations")
    before = path.read_bytes()

    with pytest.raises(SystemExit) as error:
        run_supervised_investigation.main(
            [str(investigation_id), "--yes", "--database", str(path)]
        )
    assert "Cannot open ready SQLite database" in str(error.value)
    assert path.read_bytes() == before  # refused read-only, nothing dispatched

    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        task = session.get(Task, task_id)
        assert task.status == "pending"
        assert [event.event_type for event in task.events] == ["created"]
    engine.dispose()


def test_custom_missing_database_fails_without_creating_it(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(SystemExit, match="does not exist"):
        run_supervised_investigation.main(["1", "--database", str(missing)])
    assert not missing.exists()


def test_custom_unready_database_fails_without_initializing_it(tmp_path: Path) -> None:
    unready = tmp_path / "unready.sqlite"
    unready.write_bytes(b"not an initialized sqlite schema")
    before = unready.read_bytes()
    with pytest.raises(SystemExit, match="Cannot open ready SQLite database"):
        run_supervised_investigation.main(["1", "--database", str(unready)])
    assert unready.read_bytes() == before


def test_verification_cli_gates_require_lab_mode_before_opening_database(
    operator_db: tuple[Path, int, int], capsys: pytest.CaptureFixture[str]
) -> None:
    path, investigation_id, _ = operator_db
    with pytest.raises(SystemExit) as error:
        run_supervised_investigation.main(
            [
                str(investigation_id),
                "--yes",
                "--approve-verification",
                "--verification-plan-stdin",
                "--database",
                str(path),
            ]
        )
    assert error.value.code == 2
    assert "verification approval requires --lab" in capsys.readouterr().err


def test_verification_without_plan_stays_pending(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, _ = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        asset = session.scalar(select(Asset))
        hypothesis = Hypothesis(
            asset_id=asset.id,
            category="access_control_review",
            description="Review access controls",
            status="unverified",
        )
        session.add(hypothesis)
        session.flush()
        task = create_task(
            investigation_id,
            session,
            kind="verification",
            title="Verify access control hypothesis",
            params={"hypothesis_id": hypothesis.id},
        )
        recon = session.scalar(select(Task).where(Task.kind == "recon"))
        recon.status = "completed"
        task_id = task.id
        session.commit()
    engine.dispose()
    called: list[int] = []
    monkeypatch.setattr(
        task_runner,
        "run_hypothesis_verification",
        lambda *args, **kwargs: called.append(1),
    )

    assert run_supervised_investigation.main(
        [str(investigation_id), "--yes", "--lab", "--database", str(path)]
    ) == 1
    assert called == []
    assert "provide a transient verification plan" in capsys.readouterr().out
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert session.get(Task, task_id).status == "pending"
    engine.dispose()


def test_verification_cli_rejects_plan_bound_to_another_hypothesis(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, _ = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        asset = session.scalar(select(Asset))
        first = Hypothesis(
            asset_id=asset.id,
            category="access_control_review",
            description="First review",
            status="unverified",
        )
        other = Hypothesis(
            asset_id=asset.id,
            category="access_control_review",
            description="Another review",
            status="unverified",
        )
        session.add_all([first, other])
        session.flush()
        task = create_task(
            investigation_id,
            session,
            kind="verification",
            title="Verify first hypothesis",
            params={"hypothesis_id": first.id},
        )
        recon = session.scalar(select(Task).where(Task.kind == "recon"))
        recon.status = "completed"
        first_id, other_id, task_id = first.id, other.id, task.id
        session.commit()
    engine.dispose()

    plan = json.dumps(
        {
            "hypothesis_id": other_id,
            "pairs": [
                {
                    "name": "control",
                    "url_a": "http://127.0.0.1/control-a",
                    "url_b": "http://127.0.0.1/control-b",
                    "claim_type": "cross_account_same_bytes",
                    "control_expected_match": False,
                },
                {
                    "name": "claim",
                    "url_a": "http://127.0.0.1/account",
                    "url_b": "http://127.0.0.1/account",
                    "claim_type": "cross_account_same_bytes",
                    "headers_a": {"Authorization": "account-a"},
                    "headers_b": {"Authorization": "account-b"},
                },
            ],
        }
    )
    monkeypatch.setattr("sys.stdin", StringIO(plan))
    called: list[int] = []
    monkeypatch.setattr(
        task_runner,
        "run_hypothesis_verification",
        lambda *args, **kwargs: called.append(1),
    )

    assert run_supervised_investigation.main(
        [
            str(investigation_id),
            "--yes",
            "--lab",
            "--approve-verification",
            "--verification-plan-stdin",
            "--database",
            str(path),
        ]
    ) == 1
    assert called == []
    assert "[skipped: verification_plan_mismatch]" in capsys.readouterr().out
    assert first_id != other_id
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert session.get(Task, task_id).status == "pending"
    engine.dispose()


def test_approved_verification_cli_keeps_credentials_transient(
    operator_db: tuple[Path, int, int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path, investigation_id, task_id = operator_db
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        asset = session.scalar(select(Asset))
        hypothesis = Hypothesis(
            asset_id=asset.id,
            category="access_control_review",
            description="Review access controls",
            status="unverified",
        )
        session.add(hypothesis)
        session.flush()
        task = create_task(
            investigation_id,
            session,
            kind="verification",
            title="Verify access control hypothesis",
            params={"hypothesis_id": hypothesis.id},
        )
        recon = session.scalar(select(Task).where(Task.kind == "recon"))
        recon.status = "completed"
        hypothesis_id, task_id = hypothesis.id, task.id
        session.commit()
    engine.dispose()

    secret = "transient-test-secret"
    plan = json.dumps(
        {
            "hypothesis_id": hypothesis_id,
            "pairs": [
                {
                    "name": "control",
                    "url_a": "https://api.example.test/control-a",
                    "url_b": "https://api.example.test/control-b",
                    "claim_type": "cross_account_same_bytes",
                    "control_expected_match": False,
                },
                {
                    "name": "claim",
                    "url_a": "https://api.example.test/account?token=url-secret",
                    "url_b": "https://api.example.test/account?token=url-secret",
                    "claim_type": "cross_account_same_bytes",
                    "headers_a": {"Authorization": secret},
                    "headers_b": {"Authorization": "second-transient-secret"},
                },
            ],
        }
    )
    monkeypatch.setattr("sys.stdin", StringIO(plan))
    calls: list[int] = []

    def fake_verification(*args, **kwargs):
        calls.append(1)
        outcome = SimpleNamespace(verdict=SimpleNamespace(id=777))
        return SimpleNamespace(
            outcomes=[outcome], control_outcomes=[], primary_outcomes=[outcome]
        )

    monkeypatch.setattr(task_runner, "run_hypothesis_verification", fake_verification)
    assert run_supervised_investigation.main(
        [
            str(investigation_id),
            "--yes",
            "--lab",
            "--approve-verification",
            "--verification-plan-stdin",
            "--database",
            str(path),
        ]
    ) == 0
    assert calls == [1]
    assert "Stopped after one explicitly approved verification task." in capsys.readouterr().out

    data = path.read_bytes()
    assert secret.encode() not in data
    assert b"second-transient-secret" not in data
    assert b"url-secret" not in data
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    with Session(engine) as session:
        assert session.get(Task, task_id).status == "completed"
    engine.dispose()

