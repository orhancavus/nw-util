from __future__ import annotations

import asyncio
import json
import platform
import shutil
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..network import detect_network
from ..render import render_csv, render_json
from ..services.scanner import DeviceQuery, ScanOptions, select_devices
from ..storage import DeviceStore
from .jobs import Job, JobManager
from .schemas import AliasRequest, ScanRequest, SecurityRequest, WatchRequest
from .serialize import context_dict, device_dict


def _options(request: ScanRequest) -> ScanOptions:
    return ScanOptions(
        network=request.network,
        timeout=request.timeout,
        workers=request.workers,
        max_hosts=request.max_hosts,
        deep=request.deep,
        discover=request.discover,
        mdns_timeout=request.mdns_timeout,
        record_history=request.record_history,
    )


def _require_job(manager: JobManager, job_id: str, kind: str | None = None) -> Job:
    job = manager.get(job_id, kind)
    if job is None:
        raise HTTPException(status_code=404, detail={"code": "job_not_found", "message": "Job not found"})
    return job


def _sse(event: dict[str, Any]) -> str:
    return f"id: {event['id']}\nevent: {event['event']}\ndata: {json.dumps(event)}\n\n"


async def _job_events(request: Request, job: Job) -> AsyncIterator[str]:
    try:
        last_id = int(request.headers.get("last-event-id", "0"))
    except ValueError:
        last_id = 0
    idle = 0
    while not await request.is_disconnected():
        with job.lock:
            events = [event for event in job.events if event["id"] > last_id]
            terminal = job.status in {"completed", "failed", "cancelled"}
        if events:
            idle = 0
            for event in events:
                last_id = event["id"]
                yield _sse(event)
        elif terminal:
            return
        else:
            idle += 1
            if idle >= 15:
                idle = 0
                yield ": keep-alive\n\n"
        await asyncio.sleep(0.2)


def create_app(*, store: DeviceStore | None = None) -> FastAPI:
    app_store = store or DeviceStore()
    manager = JobManager(app_store)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        manager.shutdown()

    app = FastAPI(
        title="nw-util local API",
        version=__version__,
        description="Local-only API for the nw-util network operator console.",
        lifespan=lifespan,
    )
    app.state.store = app_store
    app.state.jobs = manager
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/context")
    def context() -> dict[str, Any]:
        return context_dict(detect_network())

    @app.get("/api/v1/capabilities")
    def capabilities() -> dict[str, Any]:
        return {
            "version": __version__,
            "platform": platform.system(),
            "nmap": shutil.which("nmap") is not None,
            "mdns": True,
            "os_detection_web": False,
            "local_only": True,
            "scan_defaults": {
                "timeout": 0.5,
                "workers": 64,
                "max_hosts": 1024,
                "mdns_timeout": 2.0,
            },
        }

    @app.post("/api/v1/scans", status_code=202)
    def create_scan(body: ScanRequest) -> dict[str, Any]:
        try:
            return manager.submit_scan(_options(body)).snapshot(include_result=False)
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=429 if isinstance(exc, RuntimeError) else 422, detail=str(exc)) from exc

    @app.get("/api/v1/scans/{job_id}")
    def get_scan(job_id: str) -> dict[str, Any]:
        return _require_job(manager, job_id, "scan").snapshot()

    @app.delete("/api/v1/scans/{job_id}", status_code=202)
    def cancel_scan(job_id: str) -> dict[str, Any]:
        job = _require_job(manager, job_id, "scan")
        manager.cancel_job(job)
        return job.snapshot(include_result=False)

    @app.get("/api/v1/scans/{job_id}/events")
    def scan_events(request: Request, job_id: str) -> StreamingResponse:
        return StreamingResponse(_job_events(request, _require_job(manager, job_id, "scan")), media_type="text/event-stream")

    @app.get("/api/v1/scans/{job_id}/devices")
    def scan_devices(
        job_id: str,
        device_type: str | None = Query(default=None, alias="type"),
        status: str | None = None,
        vendor: str | None = None,
        q: str | None = None,
        sort: str = "ip",
    ) -> dict[str, Any]:
        job = _require_job(manager, job_id, "scan")
        result = job.scan_result
        if result is None:
            raise HTTPException(status_code=409, detail="Scan has not completed")
        try:
            devices = select_devices(result.devices, DeviceQuery(device_type, status, vendor, q, sort))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"devices": [device_dict(device) for device in devices], "count": len(devices)}

    @app.get("/api/v1/scans/{job_id}/export")
    def export_scan(job_id: str, format: str = "json") -> PlainTextResponse:
        job = _require_job(manager, job_id, "scan")
        result = job.scan_result
        if result is None:
            raise HTTPException(status_code=409, detail="Scan has not completed")
        if format == "csv":
            return PlainTextResponse(
                render_csv(result.devices),
                media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="nw-util-devices.csv"'},
            )
        if format == "json":
            return PlainTextResponse(
                render_json(result.devices),
                media_type="application/json",
                headers={"Content-Disposition": 'attachment; filename="nw-util-devices.json"'},
            )
        raise HTTPException(status_code=422, detail="format must be json or csv")

    @app.put("/api/v1/aliases/{target:path}")
    def put_alias(target: str, body: AliasRequest) -> dict[str, str]:
        decoded = unquote(target)
        app_store.set_alias(decoded, body.name)
        return {"target": decoded, "name": body.name.strip()}

    @app.delete("/api/v1/aliases/{target:path}")
    def delete_alias(target: str) -> dict[str, Any]:
        decoded = unquote(target)
        if not app_store.remove_alias(decoded):
            raise HTTPException(status_code=404, detail="Alias not found")
        return {"target": decoded, "removed": True}

    @app.get("/api/v1/history")
    def history(q: str | None = None) -> dict[str, Any]:
        records = app_store.history(q)
        return {"records": records, "count": len(records)}

    @app.post("/api/v1/watches", status_code=202)
    def create_watch(body: WatchRequest) -> dict[str, Any]:
        try:
            return manager.submit_watch(_options(body), body.interval).snapshot(include_result=False)
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=429 if isinstance(exc, RuntimeError) else 422, detail=str(exc)) from exc

    @app.get("/api/v1/watches/{job_id}")
    def get_watch(job_id: str) -> dict[str, Any]:
        return _require_job(manager, job_id, "watch").snapshot()

    @app.delete("/api/v1/watches/{job_id}", status_code=202)
    def stop_watch(job_id: str) -> dict[str, Any]:
        job = _require_job(manager, job_id, "watch")
        manager.cancel_job(job)
        return job.snapshot(include_result=False)

    @app.get("/api/v1/watches/{job_id}/events")
    def watch_events(request: Request, job_id: str) -> StreamingResponse:
        return StreamingResponse(_job_events(request, _require_job(manager, job_id, "watch")), media_type="text/event-stream")

    @app.post("/api/v1/security-profiles", status_code=202)
    def create_security_profile(body: SecurityRequest) -> dict[str, Any]:
        try:
            return manager.submit_security(body.target, body.timeout).snapshot(include_result=False)
        except RuntimeError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc

    @app.get("/api/v1/security-profiles/{job_id}")
    def get_security_profile(job_id: str) -> dict[str, Any]:
        return _require_job(manager, job_id, "security").snapshot()

    @app.get("/api/v1/security-profiles/{job_id}/events")
    def security_events(request: Request, job_id: str) -> StreamingResponse:
        return StreamingResponse(_job_events(request, _require_job(manager, job_id, "security")), media_type="text/event-stream")

    packaged_dist = Path(__file__).resolve().parents[1] / "web_dist"
    development_dist = Path(__file__).resolve().parents[3] / "web" / "dist"
    web_dist = packaged_dist if packaged_dist.is_dir() else development_dist
    if web_dist.is_dir():
        assets = web_dist / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
        def frontend(path: str) -> FileResponse:
            candidate = web_dist / path
            return FileResponse(candidate if candidate.is_file() else web_dist / "index.html")

    return app

