from dataclasses import asdict, replace
from pathlib import Path

import pytest
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient

from backend import main
from permission_guard.analyzer import analyze_report
from permission_guard.ingestion import parse_permission_report
from tests.test_apk_parser import _synthetic_apk, _synthetic_manifest


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(main.create_app(tmp_path / "api-scans.db"))


def test_health_and_active_policy_are_available(client: TestClient) -> None:
    health = client.get("/api/health")
    policy = client.get("/api/policies/active")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert policy.status_code == 200
    assert policy.json()["policy"]["version"] == "1.0"


@pytest.mark.parametrize(
    ("file_name", "contents", "expected_format"),
    [
        (
            "notes.json",
            b'{"app_name":"Notes","purpose":"note taking",'
            b'"permissions":["android.permission.CAMERA"]}',
            "json",
        ),
        (
            "notes.csv",
            b"app_name,purpose,permission\nNotes,note taking,android.permission.CAMERA\n",
            "csv",
        ),
    ],
)
def test_json_and_csv_uploads_use_the_existing_engine_and_persist(
    client: TestClient,
    file_name: str,
    contents: bytes,
    expected_format: str,
) -> None:
    response = client.post(
        "/api/analyze/report",
        files={"file": (file_name, contents)},
        data={"purpose": "photo editing"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["report"]["source_format"] == expected_format
    assert payload["report"]["purpose"] == "photo editing"
    assert payload["report"]["permissions"] == ["android.permission.CAMERA"]

    expected_report = replace(
        parse_permission_report(contents, file_name),
        purpose="photo editing",
    )
    expected_result = analyze_report(expected_report)
    assert payload["result"] == jsonable_encoder(asdict(expected_result))

    retrieved = client.get(f"/api/reports/{payload['analysis_id']}")
    assert retrieved.status_code == 200
    assert retrieved.json() == payload


def test_apk_upload_uses_manifest_parser(client: TestClient) -> None:
    response = client.post(
        "/api/analyze/apk",
        files={
            "file": (
                "fixture.apk",
                _synthetic_apk(_synthetic_manifest()),
                "application/vnd.android.package-archive",
            )
        },
        data={"purpose": "photography"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["report"]["source_format"] == "apk"
    assert payload["report"]["permission_source"] == "android_manifest"
    assert payload["report"]["package_name"] == "org.example.fixture"
    assert payload["report"]["purpose"] == "photography"
    assert "android.permission.CAMERA" in payload["report"]["permissions"]


def test_upload_validation_and_unknown_report_errors(client: TestClient) -> None:
    unsupported = client.post(
        "/api/analyze/report",
        files={"file": ("sample.apk", b"not-an-apk")},
    )
    malformed = client.post(
        "/api/analyze/report",
        files={"file": ("sample.json", b'{"permissions": "invalid"}')},
    )
    invalid_purpose = client.post(
        "/api/analyze/report",
        files={"file": ("sample.json", b'{"permissions": []}')},
        data={"purpose": "bad\npurpose"},
    )
    missing = client.get("/api/reports/999999")
    invalid_id = client.get("/api/reports/0")

    assert unsupported.status_code == 422
    assert malformed.status_code == 422
    assert invalid_purpose.status_code == 422
    assert missing.status_code == 404
    assert invalid_id.status_code == 422


def test_upload_size_limit_is_enforced(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main, "MAX_UPLOAD_SIZE_BYTES", 8)

    response = client.post(
        "/api/analyze/report",
        files={"file": ("oversized.json", b"x" * 9)},
    )

    assert response.status_code == 413


def test_local_analysis_remains_available_without_authentication(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/analyze/report",
        files={
            "file": (
                "local.json",
                b'{"permissions":["android.permission.CAMERA"]}',
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["report"]["permissions"] == [
        "android.permission.CAMERA"
    ]


def test_request_body_is_limited_before_multipart_processing(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main, "MAX_REQUEST_BODY_BYTES", 100)

    response = client.post(
        "/api/analyze/report",
        files={"file": ("report.json", b"x" * 200)},
        headers={"Origin": "http://127.0.0.1:5173"},
    )

    assert response.status_code == 413
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"


def test_analysis_uses_the_active_local_policy(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from permission_guard.analyzer import load_policy

    active_policy = load_policy()
    active_policy["version"] = "stage-d-test"
    monkeypatch.setattr(main, "load_active_policy", lambda: active_policy)

    response = client.post(
        "/api/analyze/report",
        files={
            "file": (
                "custom-policy.json",
                b'{"permissions":["android.permission.CAMERA"]}',
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["result"]["policy_version"] == "stage-d-test"
