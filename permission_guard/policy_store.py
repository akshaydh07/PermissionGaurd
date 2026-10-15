import json
from pathlib import Path
from typing import Any

from permission_guard.analyzer import DEFAULT_POLICY_PATH, load_policy, validate_policy
from permission_guard.errors import ReportInputError

USER_POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "user_policy.json"
)


def load_active_policy() -> dict[str, Any]:
    if USER_POLICY_PATH.exists():
        return load_policy(USER_POLICY_PATH)
    return load_policy(DEFAULT_POLICY_PATH)


def save_user_policy(policy: dict[str, Any]) -> None:
    validate_policy(policy)
    USER_POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = USER_POLICY_PATH.with_suffix(".json.tmp")
    try:
        temporary_path.write_text(
            json.dumps(policy, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(USER_POLICY_PATH)
    except OSError as error:
        raise ReportInputError(f"Unable to save local policy: {error}.") from error


def restore_default_policy() -> None:
    try:
        USER_POLICY_PATH.unlink(missing_ok=True)
    except OSError as error:
        raise ReportInputError(f"Unable to restore default policy: {error}.") from error
