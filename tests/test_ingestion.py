import json
from pathlib import Path

import pytest

from permission_guard import ingestion
from permission_guard.ingestion import ReportInputError, parse_permission_report


FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_json_report_and_preserves_permission_order() -> None:
    report = parse_permission_report(
        (FIXTURES / "reports" / "minimal_report.json").read_bytes(),
        "minimal_report.json",
    )

    assert report.app_name == "Sample Notes"
    assert report.package_name == "org.example.notes"
    assert report.purpose == "note taking"
    assert report.permissions == (
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    )
    assert report.source_format == "json"


def test_parses_csv_report_and_deduplicates_permissions() -> None:
    report = parse_permission_report(
        (FIXTURES / "reports" / "minimal_report.csv").read_text(encoding="utf-8"),
        "minimal_report.csv",
    )

    assert report.app_name == "Sample Notes"
    assert report.permissions == ("android.permission.INTERNET",)
    assert report.source_format == "csv"


def test_parses_utf8_bytes_with_bom_and_accepts_plural_csv_header() -> None:
    report = parse_permission_report(
        b"\xef\xbb\xbfapp_name,permissions\r\nSample,android.permission.CAMERA\r\n",
        "report.CSV",
    )

    assert report.app_name == "Sample"
    assert report.permissions == ("android.permission.CAMERA",)


@pytest.mark.parametrize(
    ("contents", "file_name", "message"),
    [
        ('["android.permission.CAMERA"]', "report.json", "must be an object"),
        ('{"permissions":"android.permission.CAMERA"}', "report.json", "as a list"),
        ('{"permissions":[],"surprise":true}', "report.json", "Unrecognized"),
        ('{"__reduce__":["os.system",["echo unsafe"]]}', "report.json", "Unrecognized"),
        ("permission\nandroid.permission.CAMERA extra", "report.csv", "whitespace"),
        ("\ud800", "report.json", "valid UTF-8"),
        ("app_name,permission\nOne,android.permission.CAMERA\nTwo,android.permission.RECORD_AUDIO", "report.csv", "conflicting"),
        ("permission,PERMISSION\nandroid.permission.CAMERA,android.permission.CAMERA", "report.csv", "unique"),
        ("", "report.csv", "header row"),
        ("{}", "report.txt", "Only .json and .csv"),
    ],
)
def test_rejects_invalid_reports(
    contents: str,
    file_name: str,
    message: str,
) -> None:
    with pytest.raises(ReportInputError, match=message):
        parse_permission_report(contents, file_name)


def test_five_synthetic_test_applications_are_available() -> None:
    apps = json.loads((FIXTURES / "test_apps.json").read_text(encoding="utf-8"))

    assert len(apps) >= 5
    assert all(app["app_name"] and app["purpose"] for app in apps)
    assert all(isinstance(app["permissions"], list) for app in apps)


@pytest.mark.parametrize(
    ("contents", "file_name"),
    [
        (" " * 11, "large.json"),
        (b"permission\n" + b"x" * 11, "large.csv"),
    ],
)
def test_text_report_size_limit_is_enforced(
    contents: str | bytes,
    file_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ingestion, "MAX_REPORT_SIZE_BYTES", 10)

    with pytest.raises(ReportInputError, match="must not exceed"):
        parse_permission_report(contents, file_name)
