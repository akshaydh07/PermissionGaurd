import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from permission_guard.analysis_models import AnalysisResult, Finding
from permission_guard.models import PermissionReport

DEFAULT_DATABASE_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "permission_guard.db"
)


def initialize_database(database_path: str | Path = DEFAULT_DATABASE_PATH) -> None:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                app_name TEXT,
                package_name TEXT,
                purpose TEXT,
                source_format TEXT NOT NULL,
                permission_source TEXT NOT NULL,
                score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
                risk_band TEXT NOT NULL CHECK (risk_band IN ('Low', 'Medium', 'High')),
                policy_version TEXT NOT NULL,
                report_json TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS scans_scanned_at_idx ON scans(scanned_at)"
        )


def save_scan(
    report: PermissionReport,
    result: AnalysisResult,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    initialize_database(database_path)
    scanned_at = datetime.now(timezone.utc).isoformat()
    report_json = json.dumps(asdict(report), ensure_ascii=False)
    result_json = json.dumps(asdict(result), ensure_ascii=False)
    with sqlite3.connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                scanned_at, app_name, package_name, purpose, source_format,
                permission_source, score, risk_band, policy_version,
                report_json, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scanned_at,
                report.app_name,
                report.package_name,
                report.purpose,
                report.source_format,
                report.permission_source,
                result.score,
                result.risk_band,
                result.policy_version,
                report_json,
                result_json,
            ),
        )
        return int(cursor.lastrowid)


def list_scans(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    initialize_database(database_path)
    query = """
        SELECT id, scanned_at, app_name, package_name, purpose, source_format,
               permission_source, score, risk_band, policy_version, report_json
        FROM scans
        ORDER BY scanned_at DESC, id DESC
    """
    parameters: tuple[int, ...] = ()
    if limit is not None:
        if limit < 0:
            raise ValueError("Scan limit cannot be negative.")
        query += " LIMIT ?"
        parameters = (limit,)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(query, parameters).fetchall()
    records = [dict(row) for row in rows]
    for record in records:
        record["report"] = _report_from_json(record.pop("report_json"))
    return records


def load_scan(
    scan_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> tuple[PermissionReport, AnalysisResult] | None:
    initialize_database(database_path)
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT report_json, result_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    return _report_from_json(row[0]), _result_from_json(row[1])


def delete_scan(scan_id: int, database_path: str | Path = DEFAULT_DATABASE_PATH) -> bool:
    initialize_database(database_path)
    with sqlite3.connect(database_path) as connection:
        cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount == 1


def _report_from_json(payload: str) -> PermissionReport:
    data = json.loads(payload)
    data["permissions"] = tuple(data["permissions"])
    return PermissionReport(**data)


def _result_from_json(payload: str) -> AnalysisResult:
    data = json.loads(payload)
    data["findings"] = tuple(
        Finding(
            **{
                **finding,
                "permissions": tuple(finding["permissions"]),
                "evidence": tuple(finding["evidence"]),
            }
        )
        for finding in data["findings"]
    )
    return AnalysisResult(**data)
