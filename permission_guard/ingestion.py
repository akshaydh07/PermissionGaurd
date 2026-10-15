import csv
import io
import json
from pathlib import Path
from typing import Any

from permission_guard.errors import ReportInputError
from permission_guard.models import PermissionReport
from permission_guard.normalization import (
    normalize_optional_text,
    normalize_permissions,
)


_METADATA_FIELDS = ("app_name", "package_name", "purpose")
MAX_REPORT_SIZE_BYTES = 100 * 1024 * 1024


def parse_permission_report(
    contents: str | bytes,
    file_name: str,
) -> PermissionReport:
    """Parse a JSON, CSV, or APK report without executing uploaded content."""
    suffix = Path(file_name).suffix.casefold()
    if suffix not in {".json", ".csv", ".apk"}:
        raise ReportInputError(
            "Only .json and .csv permission reports or .apk files are supported."
        )
    if suffix == ".apk":
        if not isinstance(contents, bytes):
            raise ReportInputError("APK contents must be provided as bytes.")
        from permission_guard.apk_parser import parse_apk

        return parse_apk(contents)

    if isinstance(contents, bytes):
        size = len(contents)
    elif isinstance(contents, str):
        try:
            size = len(contents.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise ReportInputError(
                "Report contents must be valid UTF-8 text."
            ) from error
    else:
        raise ReportInputError("Report contents must be text or UTF-8 bytes.")
    if size > MAX_REPORT_SIZE_BYTES:
        raise ReportInputError("Report files must not exceed 100 MB.")

    text = _decode_contents(contents)
    if suffix == ".json":
        return _parse_json(text)
    return _parse_csv(text)


def _decode_contents(contents: str | bytes) -> str:
    if isinstance(contents, bytes):
        try:
            return contents.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ReportInputError("Report files must use UTF-8 encoding.") from error
    if not isinstance(contents, str):
        raise ReportInputError("Report contents must be text or UTF-8 bytes.")
    return contents.removeprefix("\ufeff")


def _parse_json(text: str) -> PermissionReport:
    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError as error:
        raise ReportInputError(f"Invalid JSON report: {error.msg}.") from error

    if not isinstance(payload, dict):
        raise ReportInputError("A JSON report must be an object.")
    allowed_fields = {*_METADATA_FIELDS, "permissions"}
    unknown_fields = set(payload) - allowed_fields
    if unknown_fields:
        names = ", ".join(sorted(str(field) for field in unknown_fields))
        raise ReportInputError(f"Unrecognized JSON field(s): {names}.")
    if "permissions" not in payload:
        raise ReportInputError("A JSON report must include a permissions array.")

    metadata = {
        field: normalize_optional_text(payload.get(field), field)
        for field in _METADATA_FIELDS
    }
    permissions = normalize_permissions(payload["permissions"])
    return PermissionReport(
        **metadata,
        permissions=permissions,
        source_format="json",
    )


def _parse_csv(text: str) -> PermissionReport:
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        headers = reader.fieldnames
        if not headers:
            raise ReportInputError("A CSV report must include a header row.")

        normalized_headers = [header.strip().casefold() for header in headers]
        if any(not header for header in normalized_headers):
            raise ReportInputError("CSV column names cannot be blank.")
        if len(normalized_headers) != len(set(normalized_headers)):
            raise ReportInputError("CSV column names must be unique.")

        permission_headers = [
            name for name in ("permission", "permissions") if name in normalized_headers
        ]
        if len(permission_headers) != 1:
            raise ReportInputError(
                "A CSV report must include exactly one 'permission' column."
            )

        column_names = dict(zip(headers, normalized_headers))
        permission_column = permission_headers[0]
        metadata_values: dict[str, set[str]] = {
            field: set() for field in _METADATA_FIELDS
        }
        permissions: list[str] = []

        for line_number, row in enumerate(reader, start=2):
            if None in row:
                raise ReportInputError(
                    f"CSV row {line_number} has more values than the header."
                )
            if all(value is None or not value.strip() for value in row.values()):
                continue

            normalized_row = {
                column_names[column]: value for column, value in row.items()
            }
            raw_permission = normalized_row.get(permission_column)
            if raw_permission is None or not raw_permission.strip():
                raise ReportInputError(
                    f"CSV row {line_number} is missing its permission value."
                )
            permissions.append(raw_permission)

            for field in _METADATA_FIELDS:
                value = normalize_optional_text(normalized_row.get(field), field)
                if value is not None:
                    metadata_values[field].add(value)

        metadata: dict[str, str | None] = {}
        for field, values in metadata_values.items():
            if len(values) > 1:
                raise ReportInputError(
                    f"CSV rows contain conflicting values for '{field}'."
                )
            metadata[field] = next(iter(values), None)

    except csv.Error as error:
        raise ReportInputError(f"Invalid CSV report: {error}.") from error

    return PermissionReport(
        **metadata,
        permissions=normalize_permissions(permissions),
        source_format="csv",
    )
