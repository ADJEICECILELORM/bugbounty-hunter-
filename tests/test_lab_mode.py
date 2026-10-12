import ast
import ipaddress
from pathlib import Path

import pytest

from gateway.dns_pin import PinnedTarget, TargetRejected
from gateway.lab_mode import LabModeNotExplicitlyEnabled, LabPinnedTarget, pin_lab_url


def test_private_network_requires_explicit_enable_before_resolution() -> None:
    resolver_calls: list[tuple[str, int]] = []

    def resolver(hostname: str, port: int) -> list[str]:
        resolver_calls.append((hostname, port))
        return ["127.0.0.1"]

    with pytest.raises(LabModeNotExplicitlyEnabled):
        pin_lab_url(
            "http://localhost:8080/",
            allow_private_network=False,
            authorize=lambda _: True,
            resolver=resolver,
        )

    assert resolver_calls == []


def test_lab_mode_pins_private_ip_and_marks_target_as_lab() -> None:
    target = pin_lab_url(
        "http://localhost:8080/",
        allow_private_network=True,
        authorize=lambda url: url == "http://localhost:8080/",
        resolver=lambda _hostname, _port: ["127.0.0.1"],
    )

    assert isinstance(target, PinnedTarget)
    assert isinstance(target, LabPinnedTarget)
    assert target.is_lab_target is True
    assert target.addresses == (ipaddress.ip_address("127.0.0.1"),)


def test_lab_mode_still_enforces_scope_before_resolution() -> None:
    resolver_calls: list[tuple[str, int]] = []

    def resolver(hostname: str, port: int) -> list[str]:
        resolver_calls.append((hostname, port))
        return ["127.0.0.1"]

    with pytest.raises(TargetRejected, match="outside authorized scope"):
        pin_lab_url(
            "http://localhost:8080/",
            allow_private_network=True,
            authorize=lambda _: False,
            resolver=resolver,
        )

    assert resolver_calls == []


def test_only_explicit_lab_verifier_imports_lab_mode() -> None:
    repository_root = Path(__file__).parents[1]
    normal_flow_paths = [
        *(repository_root / "workers").rglob("*.py"),
        repository_root / "verification" / "http_probe.py",
        repository_root / "verification" / "diff_check.py",
        repository_root / "verification" / "evidence.py",
        repository_root / "verification" / "run_verification.py",
    ]
    violations: list[str] = []

    for source_path in normal_flow_paths:
        syntax_tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(syntax_tree):
            imported_modules: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
            elif isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
            if any(
                module == "gateway.lab_mode" or module.startswith("gateway.lab_mode.")
                for module in imported_modules
            ):
                violations.append(str(source_path.relative_to(repository_root)))

    assert violations == []

    lab_runner = (repository_root / "verification" / "lab_verification.py").read_text(
        encoding="utf-8"
    )
    assert "from gateway.lab_mode import pin_lab_url" in lab_runner


def test_allow_private_network_argument_is_required() -> None:
    with pytest.raises(TypeError):
        pin_lab_url("http://127.0.0.1/", authorize=lambda _: True)  # type: ignore[call-arg]