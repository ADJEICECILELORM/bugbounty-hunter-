from pathlib import Path

import pytest

from gateway.program_config import ProgramConfigError, load_program


def test_load_program_returns_validated_config() -> None:
    config_path = Path(__file__).parents[1] / "programs" / "example_program.yaml"

    assert load_program(str(config_path)) == {
        "name": "Example Security Program",
        "authorized_scope": ["*.example.test"],
        "excluded_scope": ["admin.example.test"],
        "rate_limit_per_minute": 30,
        "max_investigation_hours": 4,
    }


def test_missing_required_field_raises_clear_error(tmp_path: Path) -> None:
    config_path = tmp_path / "program.yaml"
    config_path.write_text(
        "name: Incomplete\nauthorized_scope: [example.test]\n",
        encoding="utf-8",
    )

    with pytest.raises(ProgramConfigError, match="Missing required.*excluded_scope"):
        load_program(str(config_path))


def test_malformed_yaml_raises_clear_error(tmp_path: Path) -> None:
    config_path = tmp_path / "program.yaml"
    config_path.write_text("name: [unterminated\n", encoding="utf-8")

    with pytest.raises(ProgramConfigError, match="Malformed YAML"):
        load_program(str(config_path))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorized_scope", "example.test"),
        ("excluded_scope", [1]),
        ("rate_limit_per_minute", True),
        ("max_investigation_hours", 0),
    ],
)
def test_malformed_fields_raise_clear_error(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    import yaml

    config = {
        "name": "Example",
        "authorized_scope": ["example.test"],
        "excluded_scope": [],
        "rate_limit_per_minute": 10,
        "max_investigation_hours": 1,
    }
    config[field] = value
    config_path = tmp_path / "program.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    with pytest.raises(ProgramConfigError):
        load_program(str(config_path))