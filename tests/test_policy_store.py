from pathlib import Path

import pytest

from permission_guard.analyzer import load_policy
from permission_guard.errors import ReportInputError
from permission_guard import policy_store


def test_policy_overrides_are_local_and_can_be_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    defaults = load_policy()
    monkeypatch.setattr(policy_store, "USER_POLICY_PATH", tmp_path / "user_policy.json")
    changed = {**defaults, "version": "test-override"}

    policy_store.save_user_policy(changed)

    assert policy_store.load_active_policy()["version"] == "test-override"
    policy_store.restore_default_policy()
    assert not policy_store.USER_POLICY_PATH.exists()
    assert policy_store.load_active_policy()["version"] == defaults["version"]


def test_invalid_policy_is_not_saved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "user_policy.json"
    monkeypatch.setattr(policy_store, "USER_POLICY_PATH", target)
    invalid = load_policy()
    invalid["scoring"]["policy_violation_points"] = -1

    with pytest.raises(ReportInputError):
        policy_store.save_user_policy(invalid)

    assert not target.exists()
