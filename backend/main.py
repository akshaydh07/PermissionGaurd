from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Path as PathParameter, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from permission_guard.analysis_models import AnalysisResult
from permission_guard.analyzer import analyze_report
from permission_guard.errors import ReportInputError
from permission_guard.ingestion import MAX_REPORT_SIZE_BYTES, parse_permission_report
from permission_guard.models import PermissionReport
from permission_guard.normalization import normalize_optional_text
from permission_guard.policy_store import load_active_policy
from permission_guard.storage import (
    DEFAULT_DATABASE_PATH,
    load_scan,
    save_scan,
)

MAX_UPLOAD_SIZE_BYTES = MAX_REPORT_SIZE_BYTES
UPLOAD_CHUNK_SIZE_BYTES = 64 * 1024
MAX_REQUEST_BODY_BYTES = MAX_UPLOAD_SIZE_BYTES + 1024 * 1024
ALLOWED_ORIGINS = ["http://127.0.0.1:5173", "http://localhost:5173"]
ANALYSIS_PATHS = {"/api/analyze/report", "/api/analyze/apk"}


class RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["path"] not in ANALYSIS_PATHS:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_REQUEST_BODY_BYTES:
                    await self._send_too_large(send)
                    return
            except ValueError:
                pass

        received_bytes = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > MAX_REQUEST_BODY_BYTES:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._send_too_large(send)

    async def _send_too_large(self, send: Any) -> None:
        body = b'{"detail":"Request body exceeds the upload limit."}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _serialize_analysis(
    analysis_id: int,
    report: PermissionReport,
    result: AnalysisResult,
) -> dict[str, Any]:
    return {
        "analysis_id": analysis_id,
        "report": asdict(report),
        "result": asdict(result),
    }


async def _read_upload(upload: UploadFile) -> bytes:
    contents = bytearray()
    while True:
        remaining = MAX_UPLOAD_SIZE_BYTES + 1 - len(contents)
        chunk = await upload.read(min(UPLOAD_CHUNK_SIZE_BYTES, remaining))
        if not chunk:
            break
        contents.extend(chunk)
        if len(contents) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=(
                    "Files must not exceed "
                    f"{MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."
                ),
            )
    return bytes(contents)


async def _analyze_upload(
    upload: UploadFile,
    purpose: str | None,
    allowed_suffixes: set[str],
    database_path: str | Path,
) -> dict[str, Any]:
    file_name = upload.filename or ""
    suffix = Path(file_name).suffix.casefold()
    try:
        if suffix not in allowed_suffixes:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Choose a file with one of these extensions: "
                    f"{', '.join(sorted(allowed_suffixes))}."
                ),
            )

        normalized_purpose = None
        if purpose is not None:
            normalized_purpose = normalize_optional_text(purpose, "purpose")
            if normalized_purpose is not None and len(normalized_purpose) > 500:
                raise ReportInputError("Purpose must not exceed 500 characters.")

        contents = await _read_upload(upload)
        report = parse_permission_report(contents, file_name)
        if normalized_purpose:
            report = replace(report, purpose=normalized_purpose)
    except ReportInputError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    else:
        result = analyze_report(report, policy=load_active_policy())
        analysis_id = save_scan(report, result, database_path)
        return _serialize_analysis(analysis_id, report, result)
    finally:
        await upload.close()


def create_app(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> FastAPI:
    app = FastAPI(
        title="PermissionGuard local analysis API",
        description="Local-only adapter for PermissionGuard's deterministic analysis engine.",
        version="1.0.0",
    )
    app.add_middleware(RequestBodyLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/analyze/report")
    async def analyze_report_upload(
        file: UploadFile = File(...),
        purpose: str | None = Form(default=None, max_length=500),
    ) -> dict[str, Any]:
        return await _analyze_upload(file, purpose, {".json", ".csv"}, database_path)

    @app.post("/api/analyze/apk")
    async def analyze_apk_upload(
        file: UploadFile = File(...),
        purpose: str | None = Form(default=None, max_length=500),
    ) -> dict[str, Any]:
        return await _analyze_upload(file, purpose, {".apk"}, database_path)

    @app.get("/api/reports/{analysis_id}")
    def get_report(
        analysis_id: int = PathParameter(gt=0),
    ) -> dict[str, Any]:
        saved_scan = load_scan(analysis_id, database_path)
        if saved_scan is None:
            raise HTTPException(status_code=404, detail="Analysis report not found.")
        report, result = saved_scan
        return _serialize_analysis(analysis_id, report, result)

    @app.get("/api/policies/active")
    def get_active_policy() -> dict[str, Any]:
        return {"policy": load_active_policy()}

    return app


app = create_app()
