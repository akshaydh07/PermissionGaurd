from permission_guard.analysis_models import AnalysisResult
from permission_guard.models import PermissionReport
from permission_guard.storage import delete_scan, list_scans, load_scan, save_scan


def _sample() -> tuple[PermissionReport, AnalysisResult]:
    report = PermissionReport(
        app_name="History Test",
        package_name="org.example.history",
        purpose="calculator",
        permissions=("android.permission.CAMERA",),
        source_format="json",
    )
    result = AnalysisResult(
        app_name=report.app_name,
        package_name=report.package_name,
        purpose=report.purpose,
        score=32,
        risk_band="Medium",
        findings=(),
        scoring_breakdown={
            "sensitivity": 6,
            "purpose_mismatch": 14,
            "policy_violations": 0,
            "combinations": 12,
        },
        policy_version="1.0",
    )
    return report, result


def test_scan_history_round_trips_report_and_findings(tmp_path) -> None:
    database_path = tmp_path / "history.db"
    report, result = _sample()

    scan_id = save_scan(report, result, database_path)
    loaded = load_scan(scan_id, database_path)
    records = list_scans(database_path)

    assert loaded == (report, result)
    assert len(records) == 1
    assert records[0]["id"] == scan_id
    assert records[0]["risk_band"] == "Medium"
    assert records[0]["report"] == report


def test_history_supports_limits_and_individual_deletion(tmp_path) -> None:
    database_path = tmp_path / "history.db"
    report, result = _sample()
    first_id = save_scan(report, result, database_path)
    second_id = save_scan(report, result, database_path)

    assert len(list_scans(database_path, limit=1)) == 1
    assert delete_scan(first_id, database_path)
    assert load_scan(first_id, database_path) is None
    assert load_scan(second_id, database_path) == (report, result)
    assert not delete_scan(first_id, database_path)


def test_scan_id_values_are_bound_and_cannot_inject_sql(tmp_path) -> None:
    database_path = tmp_path / "history.db"
    report, result = _sample()
    scan_id = save_scan(report, result, database_path)
    payload = f"{scan_id}; DROP TABLE scans;--"

    assert load_scan(payload, database_path) is None
    assert not delete_scan(payload, database_path)
    assert load_scan(scan_id, database_path) == (report, result)
    assert len(list_scans(database_path)) == 1
