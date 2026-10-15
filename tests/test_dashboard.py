import json
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from permission_guard.analyzer import analyze_report
from permission_guard.models import PermissionReport
from permission_guard import policy_store
from permission_guard.analyzer import load_policy
from permission_guard.storage import delete_scan, list_scans, load_scan, save_scan


def test_dashboard_pages_render_without_exceptions() -> None:
    app = AppTest.from_file(
        Path(__file__).parents[1] / "app.py",
        default_timeout=30,
    ).run()

    assert not app.exception
    assert app.radio[0].options == [
        "Overview",
        "Analyze App",
        "Application Report",
        "App Comparison",
        "Scan History",
        "Policy Settings",
        "Methodology & Privacy",
    ]

    for page in app.radio[0].options[1:]:
        app.radio[0].set_value(page).run()
        assert not app.exception, f"Dashboard failed while rendering {page}"


def test_analyze_page_accepts_report_and_saves_real_analysis() -> None:
    existing_ids = {record["id"] for record in list_scans()}
    app = AppTest.from_file(
        Path(__file__).parents[1] / "app.py",
        default_timeout=30,
    ).run()
    app.radio[0].set_value("Analyze App").run()
    app.file_uploader[0].upload(
        "voice_memo.json",
        (
            b'{"app_name":"Voice Memo","package_name":"org.example.ui-test",'
            b'"permissions":["android.permission.RECORD_AUDIO"]}'
        ),
        "application/json",
    ).run()
    app.text_input[0].set_value("audio recording").run()

    try:
        run_button = next(
            button for button in app.button if button.label == "Run deterministic analysis"
        )
        run_button.click().run()

        assert not app.exception
        assert any("Analysis completed" in item.value for item in app.success)
        created = [
            record for record in list_scans() if record["id"] not in existing_ids
        ]
        assert len(created) == 1
        assert created[0]["package_name"] == "org.example.ui-test"
        assert created[0]["purpose"] == "audio recording"
        assert created[0]["risk_band"] in {"Low", "Medium", "High"}
        assert created[0]["score"] > 0
        loaded = load_scan(created[0]["id"])
        assert loaded is not None
        assert loaded[0].permissions == ("android.permission.RECORD_AUDIO",)
        assert any("Voice Memo" in item.value for item in app.subheader)
        assert any("Findings · 1" in item.value for item in app.subheader)
        assert any(
            "Permission Sensitivity" in expander.label
            for expander in app.expander
        )
        assert any(
            "Can access the microphone" in markdown.value
            for markdown in app.markdown
        )
        assert any(
            "Request microphone access only" in markdown.value
            for markdown in app.markdown
        )
    finally:
        for record in list_scans():
            if record["id"] not in existing_ids:
                delete_scan(record["id"])


def test_dashboard_accepts_csv_and_synthetic_apk_uploads() -> None:
    fixture_spec = importlib.util.spec_from_file_location(
        "permission_guard_apk_fixture_factory",
        Path(__file__).with_name("test_apk_parser.py"),
    )
    assert fixture_spec is not None and fixture_spec.loader is not None
    fixture_module = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture_module)

    uploads = (
        (
            "dashboard.csv",
            (
                b"app_name,package_name,purpose,permission\n"
                b"CSV Weather,org.example.ui.csv,weather,"
                b"android.permission.INTERNET\n"
                b"CSV Weather,org.example.ui.csv,weather,"
                b"android.permission.ACCESS_FINE_LOCATION\n"
            ),
            "weather forecasts",
            "org.example.ui.csv",
        ),
        (
            "dashboard.apk",
            fixture_module._synthetic_apk(
                fixture_module._synthetic_manifest()
            ),
            "photo editing",
            "org.example.fixture",
        ),
    )
    existing_ids = {record["id"] for record in list_scans()}
    created_ids: list[int] = []
    try:
        for filename, content, purpose, package_name in uploads:
            app = AppTest.from_file(
                Path(__file__).parents[1] / "app.py",
                default_timeout=30,
            ).run()
            app.radio[0].set_value("Analyze App").run()
            app.file_uploader[0].upload(
                filename,
                content,
                "application/octet-stream",
            ).run()
            app.text_input[0].set_value(purpose).run()
            next(
                button
                for button in app.button
                if button.label == "Run deterministic analysis"
            ).click().run()

            assert not app.exception
            assert any("Analysis completed" in item.value for item in app.success)
            record = next(
                item
                for item in list_scans()
                if item["id"] not in existing_ids
                and item["id"] not in created_ids
            )
            created_ids.append(record["id"])
            loaded = load_scan(record["id"])
            assert loaded is not None
            assert loaded[0].package_name == package_name
            assert loaded[0].purpose == purpose
            assert loaded[1].score == record["score"]
    finally:
        for scan_id in created_ids:
            delete_scan(scan_id)


def test_history_open_and_delete_controls_work() -> None:
    report = PermissionReport(
        app_name="History UI Test",
        package_name="org.example.history-ui-test",
        purpose="calculator",
        permissions=("android.permission.CAMERA",),
        source_format="json",
    )
    result = analyze_report(report)
    scan_id = save_scan(report, result)
    try:
        app = AppTest.from_file(
            Path(__file__).parents[1] / "app.py",
            default_timeout=30,
        ).run()
        app.radio[0].set_value("Scan History").run()
        next(button for button in app.button if button.label == "Open report").click().run()

        assert not app.exception
        assert app.radio[0].value == "Application Report"
        assert any("History UI Test" in item.value for item in app.subheader)

        app.radio[0].set_value("Scan History").run()
        next(
            button
            for button in app.button
            if button.label == "Delete selected scan"
        ).click().run()
        assert not app.exception
        assert load_scan(scan_id) is None
    finally:
        delete_scan(scan_id)


def test_policy_settings_save_and_restore_controls_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        policy_store,
        "USER_POLICY_PATH",
        tmp_path / "user_policy.json",
    )
    defaults = load_policy()
    customized = deepcopy(defaults)
    customized["version"] = "dashboard-test"
    app = AppTest.from_file(
        Path(__file__).parents[1] / "app.py",
        default_timeout=30,
    ).run()
    app.radio[0].set_value("Policy Settings").run()
    app.text_area[0].set_value(json.dumps(customized)).run()

    next(
        button
        for button in app.button
        if button.label == "Validate and save local policy"
    ).click().run()
    assert not app.exception
    assert policy_store.load_active_policy()["version"] == "dashboard-test"

    next(
        button
        for button in app.button
        if button.label == "Restore default policy"
    ).click().run()
    assert not app.exception
    assert policy_store.load_active_policy()["version"] == defaults["version"]


def test_comparison_renders_multiple_saved_analyses() -> None:
    scan_ids: list[int] = []
    try:
        for app_name, package_name, permission in (
            (
                "Comparison Notes",
                "org.example.compare-notes",
                "android.permission.INTERNET",
            ),
            (
                "Comparison Camera",
                "org.example.compare-camera",
                "android.permission.CAMERA",
            ),
        ):
            report = PermissionReport(
                app_name=app_name,
                package_name=package_name,
                purpose="calculator",
                permissions=(permission,),
                source_format="json",
            )
            scan_ids.append(save_scan(report, analyze_report(report)))

        app = AppTest.from_file(
            Path(__file__).parents[1] / "app.py",
            default_timeout=30,
        ).run()
        app.radio[0].set_value("App Comparison").run()

        assert not app.exception
        assert len(app.multiselect[0].value) >= 2
        assert any(
            "Comparison Notes" in str(dataframe.value)
            for dataframe in app.dataframe
        )
    finally:
        for scan_id in scan_ids:
            delete_scan(scan_id)
