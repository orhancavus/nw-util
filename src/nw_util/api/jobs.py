from __future__ import annotations

import ipaddress
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..models import Neighbor
from ..network import detect_network
from ..security import inspect_ip, profile_as_dict, resolve_target
from ..services.scanner import ScanOptions, ScanResult, collect_devices, diff_devices, keyed_devices
from ..storage import DeviceStore
from .serialize import context_dict, device_dict


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Job:
    id: str
    kind: str
    status: str = "queued"
    phase: str = "queued"
    created_at: str = field(default_factory=_now)
    started_at: str | None = None
    completed_at: str | None = None
    result: Any = None
    error: str | None = None
    scan_result: ScanResult | None = None
    cancel: threading.Event = field(default_factory=threading.Event)
    events: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.RLock = field(default_factory=threading.RLock)

    def emit(self, event: str, **payload: Any) -> None:
        with self.lock:
            self.events.append(
                {
                    "id": len(self.events) + 1,
                    "event": event,
                    "timestamp": _now(),
                    **payload,
                }
            )
            if len(self.events) > 1000:
                self.events = self.events[-1000:]

    def snapshot(self, include_result: bool = True) -> dict[str, Any]:
        with self.lock:
            result = {
                "id": self.id,
                "kind": self.kind,
                "status": self.status,
                "phase": self.phase,
                "created_at": self.created_at,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "error": self.error,
            }
            if include_result and self.result is not None:
                result["result"] = self.result
            return result


class JobManager:
    def __init__(self, store: DeviceStore, *, max_workers: int = 4) -> None:
        self.store = store
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nw-util-web")
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()

    def _new(self, kind: str) -> Job:
        with self._lock:
            active = sum(job.status in {"queued", "running", "cancelling"} for job in self._jobs.values())
            if active >= 4:
                raise RuntimeError("Too many jobs are already running")
            job = Job(uuid.uuid4().hex, kind)
            self._jobs[job.id] = job
            return job

    def get(self, job_id: str, kind: str | None = None) -> Job | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return job if job and (kind is None or job.kind == kind) else None

    def latest_scan_devices(self) -> list[Neighbor]:
        with self._lock:
            jobs = list(self._jobs.values())
        for job in reversed(jobs):
            raw = job.scan_result
            if isinstance(raw, ScanResult):
                return list(raw.devices)
        return []

    def submit_scan(self, options: ScanOptions) -> Job:
        job = self._new("scan")

        def run() -> None:
            job.status = "running"
            job.started_at = _now()
            job.emit("state", status=job.status)

            def progress(phase: str) -> None:
                if job.cancel.is_set():
                    raise InterruptedError("Scan cancelled")
                job.phase = phase
                job.emit("progress", phase=phase)

            try:
                result = collect_devices(options, self.store, progress=progress)
                job.scan_result = result
                job.result = {
                    "context": context_dict(result.context),
                    "devices": [device_dict(device) for device in result.devices],
                    "device_count": len(result.devices),
                }
                job.status = "completed"
                job.phase = "complete"
                job.emit("complete", result=job.result)
            except InterruptedError:
                job.status = "cancelled"
                job.phase = "cancelled"
                job.emit("cancelled")
            except Exception as exc:  # normalized at the API boundary
                job.status = "failed"
                job.phase = "failed"
                job.error = str(exc)
                job.emit("error", message=job.error)
            finally:
                job.completed_at = _now()

        self._executor.submit(run)
        return job

    def submit_watch(self, options: ScanOptions, interval: float) -> Job:
        job = self._new("watch")

        def run() -> None:
            job.status = "running"
            job.started_at = _now()
            job.emit("state", status=job.status)
            previous: dict[str, Neighbor] = {}
            try:
                while not job.cancel.is_set():
                    result = collect_devices(
                        options,
                        self.store,
                        progress=lambda phase: job.emit("progress", phase=phase),
                    )
                    job.scan_result = result
                    current = keyed_devices(result.devices)
                    snapshot = {
                        "context": context_dict(result.context),
                        "devices": [device_dict(device) for device in result.devices],
                        "device_count": len(result.devices),
                    }
                    job.result = snapshot
                    if not previous:
                        job.emit("snapshot", result=snapshot)
                    else:
                        for kind, device in diff_devices(previous, current):
                            job.emit("device_change", change=kind, device=device_dict(device))
                    previous = current
                    if job.cancel.wait(interval):
                        break
                job.status = "cancelled"
                job.phase = "cancelled"
                job.emit("cancelled")
            except Exception as exc:
                job.status = "failed"
                job.phase = "failed"
                job.error = str(exc)
                job.emit("error", message=job.error)
            finally:
                job.completed_at = _now()

        self._executor.submit(run)
        return job

    def submit_security(self, target: str, timeout: float) -> Job:
        job = self._new("security")

        def run() -> None:
            job.status = "running"
            job.started_at = _now()
            job.phase = "resolving_target"
            job.emit("progress", phase=job.phase)
            try:
                devices = self.latest_scan_devices()
                ip = resolve_target(target, devices)
                if ip is None:
                    records = self.store.history(target)
                    if records and records[0].get("ips"):
                        ip = ipaddress.IPv4Address(records[0]["ips"][-1])
                if ip is None:
                    raise ValueError(f"Could not resolve device target: {target}")
                context = detect_network()
                if ip not in context.network:
                    raise ValueError(f"Target {ip} is outside the active local network {context.network}")
                job.phase = "inspecting_services"
                job.emit("progress", phase=job.phase)
                profile = inspect_ip(ip, timeout=timeout, os_detect=False)
                job.result = profile_as_dict(profile)
                job.status = "completed"
                job.phase = "complete"
                job.emit("complete", result=job.result)
            except Exception as exc:
                job.status = "failed"
                job.phase = "failed"
                job.error = str(exc)
                job.emit("error", message=job.error)
            finally:
                job.completed_at = _now()

        self._executor.submit(run)
        return job

    def cancel_job(self, job: Job) -> None:
        if job.status not in {"queued", "running"}:
            return
        job.status = "cancelling"
        job.phase = "cancelling"
        job.cancel.set()
        job.emit("state", status=job.status)

    def shutdown(self) -> None:
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            job.cancel.set()
        self._executor.shutdown(wait=False, cancel_futures=True)

