import hashlib
import json
import sqlite3
from datetime import datetime
from typing import Any

import pandas as pd
import streamlit as st

from permission_guard.analysis_models import AnalysisResult, Finding
from permission_guard.analyzer import analyze_report, load_policy
from permission_guard.errors import ReportInputError
from permission_guard.ingestion import MAX_REPORT_SIZE_BYTES, parse_permission_report
from permission_guard.models import PermissionReport
from permission_guard.policy_store import (
    load_active_policy,
    restore_default_policy,
    save_user_policy,
)
from permission_guard.storage import (
    delete_scan,
    list_scans,
    load_scan,
    save_scan,
)


st.set_page_config(
    page_title="PermissionGuard | Android permission analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

_NAVIGATION = [
    "Overview",
    "Analyze App",
    "Application Report",
    "App Comparison",
    "Scan History",
    "Policy Settings",
    "Methodology & Privacy",
]
_RISK_COLORS = {"Low": "#22c7a9", "Medium": "#f0b44d", "High": "#ff6577"}
_SEVERITY_COLORS = {
    "info": "#61b4ff",
    "low": "#22c7a9",
    "medium": "#f0b44d",
    "high": "#ff8b50",
    "critical": "#ff6577",
}


def _apply_theme() -> None:
    st.markdown(
        """
        <style>
        :root { color-scheme: dark; }
        .stApp { background: #081321; color: #e7f0fa; }
        [data-testid="stHeader"] { background: rgba(8, 19, 33, .92); }
        [data-testid="stSidebar"] { background: #0b1929; border-right: 1px solid #1b3147; }
        [data-testid="stMetric"] {
            background: linear-gradient(145deg, #102238, #0c1a2a);
            border: 1px solid #1b344b; padding: 18px; border-radius: 12px;
        }
        [data-testid="stMetricValue"] { color: #eaf5ff; }
        .pg-eyebrow { color: #22c7a9; letter-spacing: .13em; font-size: .74rem;
                      font-weight: 700; text-transform: uppercase; }
        .pg-subtitle { color: #91a9c0; margin-top: -.4rem; }
        .pg-risk {
            display: inline-block; padding: .28rem .7rem; border-radius: 999px;
            font-weight: 750; letter-spacing: .04em;
            background: #13283b; border: 1px solid #2a455e;
        }
        div[data-testid="stExpander"] { border-color: #203a52; border-radius: 10px; }
        div[data-testid="stDataFrame"] { border: 1px solid #203a52; border-radius: 10px; }
        .stButton > button[kind="primary"] {
            background: #087f8c; border: 1px solid #19aaae; color: white;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _page_header(title: str, description: str) -> None:
    st.markdown('<div class="pg-eyebrow">LOCAL ANDROID PERMISSION ANALYSIS</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<p class="pg-subtitle">{description}</p>', unsafe_allow_html=True)


def _risk_badge(band: str, score: int) -> None:
    color = _RISK_COLORS[band]
    st.markdown(
        f'<span class="pg-risk" style="color:{color}">{band.upper()} RISK · {score}/100</span>',
        unsafe_allow_html=True,
    )


def _history() -> list[dict[str, Any]]:
    try:
        return list_scans()
    except (OSError, ValueError) as error:
        st.error(f"Unable to load local scan history: {error}")
        return []


def _render_finding(finding: Finding, index: int) -> None:
    color = _SEVERITY_COLORS[finding.severity]
    title = (
        f"{finding.severity.upper()} · {finding.category.replace('_', ' ').title()} "
        f"· {', '.join(finding.permissions) or 'General'}"
    )
    with st.expander(title, expanded=index < 2):
        st.markdown(
            f'<span style="color:{color};font-weight:700">Severity: '
            f'{finding.severity.upper()}</span>',
            unsafe_allow_html=True,
        )
        st.write(finding.explanation)
        st.markdown("**Evidence**")
        for evidence in finding.evidence:
            st.markdown(f"- {evidence}")
        left, right = st.columns(2)
        left.metric("Score contribution", finding.score_contribution)
        right.metric("Confidence", f"{finding.confidence:.0%}")
        if finding.uncertainty:
            st.info(f"Uncertainty: {finding.uncertainty}")
        st.markdown("**Recommended action**")
        st.write(finding.recommended_action)


def _render_result(report: PermissionReport, result: AnalysisResult) -> None:
    left, right, third = st.columns([2, 1, 1])
    left.subheader(report.app_name or report.package_name or "Unnamed application")
    left.caption(report.package_name or "Package name unavailable")
    right.metric("Risk score", f"{result.score}/100")
    third.markdown("**Risk band**")
    _risk_badge(result.risk_band, result.score)

    st.caption(
        f"Purpose: {report.purpose or 'Not provided'} · "
        f"Input: {report.source_format.upper()} · "
        f"Permissions: {len(report.permissions)} · "
        f"Policy: {result.policy_version}"
    )
    with st.expander("Declared permissions", expanded=False):
        if report.permissions:
            st.dataframe(
                pd.DataFrame({"Declared permission": report.permissions}),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No permissions were declared in this report.")
    st.subheader(f"Findings · {len(result.findings)}")
    if not result.findings:
        st.success("No configured permission findings for this application.")
    else:
        severities = ["All"] + sorted(
            {finding.severity.title() for finding in result.findings}
        )
        selected_severity = st.selectbox(
            "Filter findings by severity",
            severities,
            key="report_severity_filter",
        )
        visible_findings = [
            finding
            for finding in result.findings
            if selected_severity == "All"
            or finding.severity.casefold() == selected_severity.casefold()
        ]
        for index, finding in enumerate(visible_findings):
            _render_finding(finding, index)
    with st.expander("Scoring breakdown"):
        st.dataframe(
            pd.DataFrame(
                [
                    {"Scoring component": key.replace("_", " ").title(), "Points": value}
                    for key, value in result.scoring_breakdown.items()
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )
        st.caption(
            "The total is capped at 100. Sensitivity is counted once per known "
            "permission; correlated mismatch/policy and overlapping combination "
            "contributions are de-duplicated."
        )


def _overview() -> None:
    _page_header(
        "PermissionGuard",
        "A local-first view of declared Android permissions and policy-driven risk.",
    )
    records = _history()
    latest_by_app: dict[str, dict[str, Any]] = {}
    for record in records:
        identity = (
            record["package_name"]
            or record["app_name"]
            or f"scan-{record['id']}"
        )
        latest_by_app.setdefault(identity, record)
    latest_records = list(latest_by_app.values())
    high = sum(record["risk_band"] == "High" for record in latest_records)
    medium = sum(record["risk_band"] == "Medium" for record in latest_records)
    low = sum(record["risk_band"] == "Low" for record in latest_records)
    total_findings = 0
    for record in latest_records:
        loaded = load_scan(record["id"])
        if loaded:
            total_findings += len(loaded[1].findings)

    metrics = st.columns(5)
    metrics[0].metric("Apps analyzed", len(latest_records))
    metrics[1].metric("High risk", high, delta_color="inverse")
    metrics[2].metric("Medium risk", medium)
    metrics[3].metric("Low risk", low)
    metrics[4].metric("Total findings", total_findings)
    st.subheader("Risk distribution")
    distribution = pd.DataFrame(
        {"Applications": [low, medium, high]},
        index=["Low", "Medium", "High"],
    )
    st.bar_chart(distribution, color=["#22c7a9"])

    st.subheader("Recent scans")
    if not records:
        st.info("No scans yet. Open **Analyze App** to start a local analysis.")
        return
    recent = records[:8]
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Scanned": _format_timestamp(record["scanned_at"]),
                    "Application": record["app_name"] or "Unnamed application",
                    "Package": record["package_name"] or "—",
                    "Purpose": record["purpose"] or "Not provided",
                    "Risk": f"{record['risk_band']} · {record['score']}/100",
                    "Input": record["source_format"].upper(),
                }
                for record in recent
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )


def _analyze_app() -> None:
    _page_header(
        "Analyze App",
        "Inspect an APK manifest or import a normalized JSON/CSV permission report.",
    )
    st.info(
        "Analysis runs locally. APKs are statically parsed and never installed or "
        "executed. Manifest declarations do not indicate device grants or runtime use."
    )
    upload = st.file_uploader(
        "Choose an APK, JSON, or CSV report",
        type=["apk", "json", "csv"],
        help="Maximum upload size: 100 MB. Files remain on this machine.",
    )
    if upload is None:
        return
    if upload.size > MAX_REPORT_SIZE_BYTES:
        st.error("Files must not exceed 100 MB.")
        return

    try:
        report = parse_permission_report(upload.getvalue(), upload.name)
    except ReportInputError as error:
        st.error(str(error))
        return

    purpose = st.text_input(
        "Application purpose",
        value=report.purpose or "",
        placeholder="e.g. navigation, audio recording, photo editing",
        help="Enter or correct the application's declared purpose for policy matching.",
    )
    if st.button("Run deterministic analysis", type="primary"):
        report = PermissionReport(
            app_name=report.app_name,
            package_name=report.package_name,
            purpose=purpose.strip() or None,
            permissions=report.permissions,
            source_format=report.source_format,
            permission_source=report.permission_source,
        )
        try:
            result = analyze_report(report, load_active_policy())
            scan_id = save_scan(report, result)
        except (ReportInputError, OSError) as error:
            st.error(f"Analysis could not be completed: {error}")
            return
        st.session_state["selected_scan_id"] = scan_id
        st.session_state["analysis_complete"] = True

    if st.session_state.pop("analysis_complete", False):
        st.success("Analysis completed and saved to local scan history.")
    scan_id = st.session_state.get("selected_scan_id")
    if scan_id is not None:
        stored = load_scan(scan_id)
        if stored:
            _render_result(*stored)


def _application_report() -> None:
    _page_header(
        "Application Report",
        "Review the full evidence, scoring contributions, uncertainty, and remediation.",
    )
    records = _history()
    if not records:
        st.info("Analyze an app first, or open a saved report from Scan History.")
        return
    ids = [record["id"] for record in records]
    current_id = st.session_state.get("selected_scan_id")
    default_index = ids.index(current_id) if current_id in ids else 0
    scan_id = st.selectbox(
        "Select saved application",
        ids,
        index=default_index,
        format_func=lambda value: _scan_label(
            next(record for record in records if record["id"] == value)
        ),
    )
    loaded = load_scan(scan_id)
    if loaded:
        _render_result(*loaded)


def _comparison() -> None:
    _page_header(
        "App Comparison",
        "Compare saved analyses by risk, declared permissions, findings, and policy violations.",
    )
    records = _history()
    if len(records) < 2:
        st.info("At least two saved scans are needed for comparison.")
        return
    ids = [record["id"] for record in records]
    selected_ids = st.multiselect(
        "Applications to compare",
        ids,
        default=ids[: min(4, len(ids))],
        format_func=lambda value: _scan_label(
            next(record for record in records if record["id"] == value)
        ),
    )
    if not selected_ids:
        st.info("Select one or more saved scans.")
        return

    comparison: list[dict[str, Any]] = []
    for scan_id in selected_ids:
        loaded = load_scan(scan_id)
        if loaded is None:
            continue
        report, result = loaded
        comparison.append(
            {
                "Scan": scan_id,
                "Application": report.app_name or report.package_name or "Unnamed",
                "Risk score": result.score,
                "Risk band": result.risk_band,
                "Permissions": len(report.permissions),
                "Findings": len(result.findings),
                "Policy violations": sum(
                    finding.category == "policy_violation"
                    for finding in result.findings
                ),
                "Declared permissions": ", ".join(report.permissions) or "None",
                "_result": result,
            }
        )
    if not comparison:
        st.info("No selected scan records could be loaded.")
        return
    st.bar_chart(
        pd.DataFrame(
            {
                item["Application"]: item["Risk score"]
                for item in comparison
            },
            index=["Risk score"],
        ).T
    )
    st.dataframe(
        pd.DataFrame([{key: value for key, value in item.items() if not key.startswith("_")} for item in comparison]),
        hide_index=True,
        use_container_width=True,
    )
    for item in comparison:
        violations = [
            finding
            for finding in item["_result"].findings
            if finding.category == "policy_violation"
        ]
        with st.expander(f"{item['Application']} · policy violations"):
            if violations:
                for finding in violations:
                    st.warning(
                        f"{', '.join(finding.permissions)} — "
                        f"{finding.recommended_action}"
                    )
            else:
                st.success("No configured organizational policy violations.")


def _scan_history() -> None:
    _page_header(
        "Scan History",
        "Saved reports and findings stay in the local SQLite database.",
    )
    records = _history()
    if not records:
        st.info("There are no saved scans.")
        return
    query = st.text_input("Filter by app name, package, or purpose")
    filtered = [
        record
        for record in records
        if not query
        or query.casefold()
        in " ".join(
            str(record[field] or "")
            for field in ("app_name", "package_name", "purpose")
        ).casefold()
    ]
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "ID": record["id"],
                    "Scanned": _format_timestamp(record["scanned_at"]),
                    "Application": record["app_name"] or "Unnamed application",
                    "Package": record["package_name"] or "—",
                    "Purpose": record["purpose"] or "Not provided",
                    "Score": record["score"],
                    "Risk": record["risk_band"],
                    "Source": record["source_format"].upper(),
                }
                for record in filtered
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )
    if not filtered:
        st.info("No scans match this filter.")
        return
    selected_id = st.selectbox(
        "Select a scan to open or delete",
        [record["id"] for record in filtered],
        format_func=lambda value: _scan_label(
            next(record for record in filtered if record["id"] == value)
        ),
    )
    open_column, delete_column = st.columns(2)
    open_column.button(
        "Open report",
        type="primary",
        on_click=_open_saved_report,
        args=(selected_id,),
    )
    if delete_column.button("Delete selected scan", type="secondary"):
        if delete_scan(selected_id):
            if st.session_state.get("selected_scan_id") == selected_id:
                st.session_state.pop("selected_scan_id")
            st.success(f"Scan {selected_id} deleted.")
            st.rerun()
        else:
            st.error("The scan was not found; no record was deleted.")


def _open_saved_report(scan_id: int) -> None:
    st.session_state["selected_scan_id"] = scan_id
    st.session_state["page"] = "Application Report"


def _policy_settings() -> None:
    _page_header(
        "Policy Settings",
        "Review and safely configure local analysis rules and scoring weights.",
    )
    try:
        policy = load_active_policy()
    except ReportInputError as error:
        st.error(f"Active policy is invalid: {error}")
        st.warning("Showing the packaged default policy so it can be restored.")
        policy = load_policy()

    st.caption(
        f"Active policy version: {policy['version']} · "
        f"{len(policy['permissions'])} permission definitions · "
        f"{len(policy['combinations'])} combination rules"
    )
    st.markdown("#### Risk weights")
    st.dataframe(
        pd.DataFrame(
            [
                {"Sensitivity": level.title(), "Points": points}
                for level, points in policy["scoring"]["sensitivity_points"].items()
            ]
            + [
                {
                    "Sensitivity": "Purpose mismatch",
                    "Points": policy["scoring"]["purpose_mismatch_points"],
                },
                {
                    "Sensitivity": "Policy violation",
                    "Points": policy["scoring"]["policy_violation_points"],
                }
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )
    st.markdown("#### Purpose mappings & organizational denylist")
    purpose_column, denied_column = st.columns(2)
    purpose_column.dataframe(
        pd.DataFrame(
            [
                {"Purpose entered": alias, "Policy category": canonical}
                for alias, canonical in policy["purpose_aliases"].items()
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )
    if policy["denied_permissions"]:
        denied_column.dataframe(
            pd.DataFrame(
                {"Denied permission": policy["denied_permissions"]}
            ),
            hide_index=True,
            use_container_width=True,
        )
    else:
        denied_column.info("No permissions are currently denied by policy.")
    st.markdown("#### Combination rules")
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Rule": rule["id"],
                    "Permission groups": " + ".join(rule["groups"]),
                    "Severity": rule["severity"].title(),
                    "Points": rule["score"],
                    "Confidence": f"{rule['confidence']:.0%}",
                }
                for rule in policy["combinations"]
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )
    st.markdown("#### Permission catalog")
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Permission": permission,
                    "Sensitivity": definition["sensitivity"].title(),
                    "Purpose justifications": ", ".join(
                        definition["justified_purposes"]
                    ),
                    "Impact": definition["impact"],
                }
                for permission, definition in policy["permissions"].items()
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )

    editor_key = "policy_json_editor_" + hashlib.sha256(
        json.dumps(policy, sort_keys=True).encode("utf-8")
    ).hexdigest()[:12]
    editor_value = st.text_area(
        "Edit complete policy JSON",
        value=json.dumps(policy, indent=2, ensure_ascii=False),
        height=460,
        key=editor_key,
        help="The policy is validated before it is saved locally.",
    )
    save_column, restore_column = st.columns(2)
    if save_column.button("Validate and save local policy", type="primary"):
        try:
            candidate = json.loads(editor_value)
            save_user_policy(candidate)
        except json.JSONDecodeError as error:
            st.error(f"Policy JSON syntax error at line {error.lineno}: {error.msg}.")
        except (ReportInputError, OSError) as error:
            st.error(str(error))
        else:
            st.success("Validated policy saved locally. New analyses will use it.")
            st.rerun()
    if restore_column.button("Restore default policy"):
        try:
            restore_default_policy()
        except ReportInputError as error:
            st.error(str(error))
        else:
            st.success("Default policy restored.")
            st.rerun()


def _methodology() -> None:
    _page_header(
        "Methodology & Privacy",
        "Understand what the analysis can—and cannot—conclude.",
    )
    st.subheader("Deterministic scoring")
    st.write(
        "PermissionGuard applies local JSON policy weights to known permission "
        "sensitivity, purpose mismatches, organizational policy violations, and "
        "configured suspicious permission combinations. The total is capped at "
        "100. Sensitivity contributes once per known permission; for a permission "
        "with both a purpose mismatch and a denylist violation, only the larger "
        "increment is counted. Overlapping combination rules share their largest "
        "contribution."
    )
    st.dataframe(
        pd.DataFrame(
            [
                {"Band": "Low", "Score": "0–29", "Color": "Teal"},
                {"Band": "Medium", "Score": "30–59", "Color": "Amber"},
                {"Band": "High", "Score": "60–100", "Color": "Coral"},
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )
    st.subheader("Static-analysis limitations")
    st.markdown(
        "- A manifest declaration is not proof a permission was granted or used.\n"
        "- This tool does not inspect device runtime behavior, network traffic, "
        "or user consent.\n"
        "- Purpose mappings and severity labels are policy heuristics and may "
        "not fit every legitimate application.\n"
        "- Permission combinations are review indicators, never proof of "
        "malicious behavior.\n"
        "- Unknown permissions and purposes are explicitly treated as uncertain."
    )
    st.subheader("Local processing and privacy")
    st.markdown(
        "- APKs are parsed statically; they are never installed or executed.\n"
        "- Uploaded report bytes are passed to local parsers and are not sent to "
        "external services.\n"
        "- Scan history and any customized policy are stored on this machine in "
        "`data/permission_guard.db` and `data/user_policy.json`.\n"
        "- Delete history entries individually from **Scan History**. No Android "
        "permissions are revoked automatically."
    )


def _format_timestamp(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def _scan_label(record: dict[str, Any]) -> str:
    app = record["app_name"] or record["package_name"] or "Unnamed application"
    return (
        f"#{record['id']} · {app} · {record['risk_band']} {record['score']}/100 · "
        f"{_format_timestamp(record['scanned_at'])}"
    )


def main() -> None:
    _apply_theme()
    with st.sidebar:
        st.markdown("## 🛡️ PermissionGuard")
        st.caption("Android permission intelligence · local-only")
        current_page = st.session_state.get("page", _NAVIGATION[0])
        page_index = _NAVIGATION.index(current_page) if current_page in _NAVIGATION else 0
        page = st.radio(
            "Navigation",
            _NAVIGATION,
            index=page_index,
            label_visibility="collapsed",
            key="page",
        )
        st.divider()
        st.caption("Static analysis · deterministic rules · no external AI")

    try:
        if page == "Overview":
            _overview()
        elif page == "Analyze App":
            _analyze_app()
        elif page == "Application Report":
            _application_report()
        elif page == "App Comparison":
            _comparison()
        elif page == "Scan History":
            _scan_history()
        elif page == "Policy Settings":
            _policy_settings()
        else:
            _methodology()
    except sqlite3.Error as error:
        st.error(f"Local scan-history database error: {error}")


if __name__ == "__main__":
    main()
