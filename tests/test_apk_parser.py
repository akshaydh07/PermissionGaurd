import struct
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from permission_guard import apk_parser
from permission_guard.errors import ReportInputError
from permission_guard.ingestion import parse_permission_report


ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
NO_INDEX = 0xFFFFFFFF


def _length8(length: int) -> bytes:
    if length > 0x7F:
        return bytes(((length >> 8) | 0x80, length & 0xFF))
    return bytes((length,))


def _string_pool(strings: list[str]) -> bytes:
    encoded_strings = bytearray()
    offsets: list[int] = []
    for value in strings:
        encoded = value.encode("utf-8")
        offsets.append(len(encoded_strings))
        encoded_strings.extend(_length8(len(value)))
        encoded_strings.extend(_length8(len(encoded)))
        encoded_strings.extend(encoded)
        encoded_strings.append(0)

    header_size = 28
    strings_start = header_size + len(offsets) * 4
    size = strings_start + len(encoded_strings)
    header = struct.pack(
        "<HHIIIIII",
        0x0001,
        header_size,
        size,
        len(strings),
        0,
        0x00000100,
        strings_start,
        0,
    )
    return header + struct.pack(f"<{len(offsets)}I", *offsets) + encoded_strings


def _node_header(chunk_type: int, size: int, header_size: int = 16) -> bytes:
    return struct.pack("<HHIII", chunk_type, header_size, size, 1, NO_INDEX)


def _namespace_chunk(chunk_type: int, prefix_index: int, uri_index: int) -> bytes:
    return _node_header(chunk_type, 24) + struct.pack(
        "<II", prefix_index, uri_index
    )


def _attribute(
    namespace_index: int,
    name_index: int,
    value_index: int,
) -> bytes:
    return struct.pack(
        "<IIIHBBI",
        namespace_index,
        name_index,
        value_index,
        8,
        0,
        0x03,
        value_index,
    )


def _start_element(
    namespace_index: int,
    name_index: int,
    attributes: list[bytes],
) -> bytes:
    extension = struct.pack(
        "<IIHHHHHH",
        namespace_index,
        name_index,
        20,
        20,
        len(attributes),
        0,
        0,
        0,
    )
    size = 16 + len(extension) + sum(map(len, attributes))
    return _node_header(0x0102, size) + extension + b"".join(attributes)


def _end_element(namespace_index: int, name_index: int) -> bytes:
    return _node_header(0x0103, 24) + struct.pack(
        "<II", namespace_index, name_index
    )


def _synthetic_manifest(
    *,
    app_label: str | None = "Fixture App",
    package_name: str | None = "org.example.fixture",
) -> bytes:
    strings = [
        "android",
        ANDROID_NAMESPACE,
        "manifest",
        "package",
        package_name or "",
        "uses-permission",
        "name",
        "android.permission.CAMERA",
        "android.permission.CAMERA",
        "permission",
        "org.example.CUSTOM",
        "application",
        "label",
        app_label or "",
    ]
    indexes = {value: index for index, value in enumerate(strings)}
    namespace = indexes[ANDROID_NAMESPACE]

    chunks = [
        _string_pool(strings),
        _namespace_chunk(0x0100, indexes["android"], namespace),
        _start_element(
            NO_INDEX,
            indexes["manifest"],
            (
                [
                    _attribute(
                        NO_INDEX,
                        indexes["package"],
                        indexes[package_name],
                    )
                ]
                if package_name
                else []
            ),
        ),
        _start_element(
            NO_INDEX,
            indexes["uses-permission"],
            [
                _attribute(
                    namespace,
                    indexes["name"],
                    indexes["android.permission.CAMERA"],
                )
            ],
        ),
        _end_element(NO_INDEX, indexes["uses-permission"]),
        _start_element(
            NO_INDEX,
            indexes["permission"],
            [
                _attribute(
                    namespace,
                    indexes["name"],
                    indexes["org.example.CUSTOM"],
                )
            ],
        ),
        _end_element(NO_INDEX, indexes["permission"]),
        _start_element(
            NO_INDEX,
            indexes["application"],
            (
                [
                    _attribute(
                        namespace,
                        indexes["label"],
                        indexes[app_label],
                    )
                ]
                if app_label
                else []
            ),
        ),
        _end_element(NO_INDEX, indexes["application"]),
        _end_element(NO_INDEX, indexes["manifest"]),
        _namespace_chunk(0x0101, indexes["android"], namespace),
    ]
    document_size = 8 + sum(map(len, chunks))
    return (
        struct.pack("<HHI", 0x0003, 8, document_size)
        + b"".join(chunks)
    )


def _synthetic_apk(manifest: bytes | None = None) -> bytes:
    apk_contents = BytesIO()
    with ZipFile(apk_contents, "w", ZIP_DEFLATED) as archive:
        if manifest is not None:
            archive.writestr("AndroidManifest.xml", manifest)
    return apk_contents.getvalue()


def test_apk_is_extracted_through_shared_report_ingestion() -> None:
    report = parse_permission_report(
        _synthetic_apk(_synthetic_manifest()),
        "synthetic.apk",
    )

    assert report.app_name == "Fixture App"
    assert report.package_name == "org.example.fixture"
    assert report.purpose is None
    assert report.permissions == ("android.permission.CAMERA",)
    assert report.source_format == "apk"
    assert report.permission_source == "android_manifest"


def test_apk_extraction_handles_missing_label_and_package() -> None:
    report = parse_permission_report(
        _synthetic_apk(_synthetic_manifest(app_label=None, package_name=None)),
        "no_metadata.apk",
    )

    assert report.app_name is None
    assert report.package_name is None
    assert report.permissions == ("android.permission.CAMERA",)


@pytest.mark.parametrize(
    ("contents", "file_name", "message"),
    [
        (b"not an apk", "broken.apk", "APK archive"),
        (_synthetic_apk(), "missing_manifest.apk", "exactly one"),
        (_synthetic_apk(b"not binary xml"), "bad_manifest.apk", "valid"),
        (_synthetic_apk(_synthetic_manifest()), "report.txt", "supported"),
    ],
)
def test_apk_ingestion_rejects_invalid_or_unsupported_inputs(
    contents: bytes,
    file_name: str,
    message: str,
) -> None:
    with pytest.raises(ReportInputError, match=message):
        parse_permission_report(contents, file_name)


def test_apk_ingestion_requires_bytes() -> None:
    with pytest.raises(ReportInputError, match="provided as bytes"):
        parse_permission_report("not bytes", "sample.apk")


def test_apk_size_limit_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_parser, "MAX_APK_SIZE_BYTES", 4)

    with pytest.raises(ReportInputError, match="must not exceed"):
        parse_permission_report(b"12345", "large.apk")


def test_archive_path_traversal_entry_is_never_extracted(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "traversal.apk"
    with ZipFile(archive_path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", _synthetic_manifest())
        archive.writestr("../../outside.txt", "must not be written")

    def reject_extraction(*args, **kwargs) -> None:
        raise AssertionError(
            f"APK parser must not extract archive entries: {args}, {kwargs}"
        )

    monkeypatch.setattr(ZipFile, "extract", reject_extraction)
    monkeypatch.setattr(ZipFile, "extractall", reject_extraction)
    report = parse_permission_report(archive_path.read_bytes(), "traversal.apk")

    assert report.package_name == "org.example.fixture"
