from io import BytesIO
import zlib
from zipfile import BadZipFile, ZipFile

from permission_guard.errors import ReportInputError
from permission_guard.models import PermissionReport
from permission_guard.normalization import normalize_optional_text, normalize_permissions

MAX_APK_SIZE_BYTES = 100 * 1024 * 1024
MAX_MANIFEST_SIZE_BYTES = 10 * 1024 * 1024
MAX_RESOURCES_SIZE_BYTES = 32 * 1024 * 1024
MAX_APK_ENTRIES = 20_000


def parse_apk(contents: bytes) -> PermissionReport:
    """Extract static manifest metadata and declared permissions from APK bytes."""
    if not isinstance(contents, bytes):
        raise ReportInputError("APK contents must be provided as bytes.")
    if not contents:
        raise ReportInputError("The APK file is empty.")
    if len(contents) > MAX_APK_SIZE_BYTES:
        raise ReportInputError(
            f"APK files must not exceed {MAX_APK_SIZE_BYTES // (1024 * 1024)} MB."
        )

    _validate_apk_archive(contents)

    try:
        from androguard.core.apk import APK

        apk = APK(contents, raw=True)
        if not apk.is_valid_APK():
            raise ReportInputError(
                "The APK does not contain a valid, parseable Android manifest."
            )

        package_name = normalize_optional_text(apk.get_package(), "package_name")
        app_name = normalize_optional_text(apk.get_app_name(), "app_name")
        permissions = normalize_permissions(apk.get_permissions())
    except ReportInputError:
        raise
    except Exception as error:
        raise ReportInputError(
            f"Unable to extract APK manifest data ({type(error).__name__})."
        ) from error

    return PermissionReport(
        app_name=app_name,
        package_name=package_name,
        purpose=None,
        permissions=permissions,
        source_format="apk",
        permission_source="android_manifest",
    )


def _validate_apk_archive(contents: bytes) -> None:
    try:
        with ZipFile(BytesIO(contents)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_APK_ENTRIES:
                raise ReportInputError(
                    f"APK archives must contain no more than {MAX_APK_ENTRIES} files."
                )

            manifest_entries = [
                entry for entry in entries if entry.filename == "AndroidManifest.xml"
            ]
            if len(manifest_entries) != 1:
                raise ReportInputError(
                    "The APK must contain exactly one AndroidManifest.xml."
                )
            manifest_entry = manifest_entries[0]
            if manifest_entry.file_size == 0:
                raise ReportInputError("The APK AndroidManifest.xml is empty.")
            if manifest_entry.file_size > MAX_MANIFEST_SIZE_BYTES:
                raise ReportInputError("The APK AndroidManifest.xml is too large.")

            resource_entries = [
                entry for entry in entries if entry.filename == "resources.arsc"
            ]
            if len(resource_entries) > 1:
                raise ReportInputError("The APK contains duplicate resources.arsc files.")
            if (
                resource_entries
                and resource_entries[0].file_size > MAX_RESOURCES_SIZE_BYTES
            ):
                raise ReportInputError("The APK resources.arsc file is too large.")

            archive.read(manifest_entry)
    except ReportInputError:
        raise
    except (
        BadZipFile,
        EOFError,
        NotImplementedError,
        OSError,
        RuntimeError,
        zlib.error,
    ) as error:
        raise ReportInputError(
            f"The uploaded file is not a readable APK archive ({type(error).__name__})."
        ) from error
