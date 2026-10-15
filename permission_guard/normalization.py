from typing import Any

from permission_guard.errors import ReportInputError


def normalize_optional_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ReportInputError(f"'{field}' must be a string.")
    normalized = value.strip()
    if any(character in normalized for character in ("\x00", "\r", "\n")):
        raise ReportInputError(f"'{field}' contains an invalid control character.")
    return normalized or None


def normalize_permissions(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ReportInputError("Permissions must be provided as a list.")

    normalized: list[str] = []
    seen: set[str] = set()
    for index, raw_permission in enumerate(value):
        permission = normalize_optional_text(raw_permission, f"permissions[{index}]")
        if permission is None:
            raise ReportInputError(f"permissions[{index}] cannot be blank.")
        if any(character.isspace() for character in permission):
            raise ReportInputError(
                f"permissions[{index}] cannot contain whitespace."
            )
        if permission not in seen:
            seen.add(permission)
            normalized.append(permission)
    return tuple(normalized)
