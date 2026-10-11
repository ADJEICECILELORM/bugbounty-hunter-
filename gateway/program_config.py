"""Load and validate a bug bounty program configuration from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from gateway.scope_policy import ScopePolicy

_REQUIRED_FIELDS = {
    "name",
    "authorized_scope",
    "excluded_scope",
    "rate_limit_per_minute",
    "max_investigation_hours",
}


class ProgramConfigError(ValueError):
    """Raised when a program configuration is missing or has invalid data."""


def _validate_scope_list(data: dict[str, Any], field: str) -> list[str]:
    value = data[field]
    if not isinstance(value, list) or any(not isinstance(entry, str) for entry in value):
        raise ProgramConfigError(f"'{field}' must be a list of strings")
    if field == "authorized_scope" and not value:
        raise ProgramConfigError("'authorized_scope' must contain at least one entry")
    return value


def load_program(path: str) -> dict[str, Any]:
    """Read a YAML program file and return its validated fields."""
    config_path = Path(path)
    try:
        with config_path.open(encoding="utf-8") as config_file:
            data = yaml.safe_load(config_file)
    except yaml.YAMLError as error:
        raise ProgramConfigError(f"Malformed YAML in {config_path}") from error

    if not isinstance(data, dict):
        raise ProgramConfigError("Program configuration must be a YAML mapping")

    missing = sorted(_REQUIRED_FIELDS - data.keys())
    if missing:
        raise ProgramConfigError(f"Missing required program fields: {', '.join(missing)}")

    name = data["name"]
    if not isinstance(name, str) or not name.strip():
        raise ProgramConfigError("'name' must be a non-empty string")

    authorized_scope = _validate_scope_list(data, "authorized_scope")
    excluded_scope = _validate_scope_list(data, "excluded_scope")
    try:
        ScopePolicy(authorized_scope, excluded_scope)
    except ValueError as error:
        raise ProgramConfigError(f"Invalid hostname scope: {error}") from error

    rate_limit = data["rate_limit_per_minute"]
    if isinstance(rate_limit, bool) or not isinstance(rate_limit, int) or rate_limit < 1:
        raise ProgramConfigError("'rate_limit_per_minute' must be a positive integer")

    max_hours = data["max_investigation_hours"]
    if isinstance(max_hours, bool) or not isinstance(max_hours, int) or max_hours < 1:
        raise ProgramConfigError("'max_investigation_hours' must be a positive integer")

    return {
        **data,
        "name": name.strip(),
        "authorized_scope": authorized_scope,
        "excluded_scope": excluded_scope,
        "rate_limit_per_minute": rate_limit,
        "max_investigation_hours": max_hours,
    }