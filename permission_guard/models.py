from dataclasses import dataclass
from typing import Literal


SourceFormat = Literal["json", "csv", "apk"]
PermissionSource = Literal["report", "android_manifest"]


@dataclass(frozen=True, slots=True)
class PermissionReport:
    """Normalized permission data; APK permissions are manifest declarations only."""

    app_name: str | None
    package_name: str | None
    purpose: str | None
    permissions: tuple[str, ...]
    source_format: SourceFormat
    permission_source: PermissionSource = "report"
