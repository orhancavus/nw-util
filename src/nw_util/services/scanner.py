from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from ..discovery import discover_mdns, merge_mdns
from ..enrich import enrich_devices
from ..models import Neighbor, NetworkContext
from ..network import detect_network, scan
from ..query import filter_devices, sort_devices
from ..storage import DeviceStore, device_key


ProgressCallback = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class ScanOptions:
    network: str | None = None
    timeout: float = 0.5
    workers: int = 64
    max_hosts: int = 1024
    deep: bool = False
    discover: bool = False
    mdns_timeout: float = 2.0
    record_history: bool = True

    def validate(self) -> None:
        values = (self.timeout, self.workers, self.max_hosts, self.mdns_timeout)
        if any(value <= 0 for value in values):
            raise ValueError("timeout, workers, max_hosts, and mdns_timeout must be positive")
        if self.workers > 512:
            raise ValueError("workers cannot exceed 512")
        if self.max_hosts > 65_536:
            raise ValueError("max_hosts cannot exceed 65,536")


@dataclass(frozen=True, slots=True)
class DeviceQuery:
    device_type: str | None = None
    status: str | None = None
    vendor: str | None = None
    text: str | None = None
    sort: str = "ip"


@dataclass(frozen=True, slots=True)
class ScanResult:
    context: NetworkContext
    devices: tuple[Neighbor, ...]


def collect_devices(
    options: ScanOptions,
    store: DeviceStore,
    *,
    progress: ProgressCallback | None = None,
    context: NetworkContext | None = None,
) -> ScanResult:
    options.validate()
    emit = progress or (lambda _phase: None)
    emit("detecting_network")
    context = context or detect_network(options.network)
    emit("probing_hosts")
    devices = scan(
        context,
        timeout=options.timeout,
        workers=options.workers,
        max_hosts=options.max_hosts,
    )
    if options.discover or options.deep:
        emit("discovering_mdns")
        devices = merge_mdns(devices, discover_mdns(options.mdns_timeout), context)
    if options.deep:
        emit("enriching_services")
        devices = enrich_devices(devices, timeout=options.timeout, workers=options.workers)
    devices = store.apply_aliases(devices)
    if options.record_history:
        emit("saving_history")
        store.record(devices)
    emit("complete")
    return ScanResult(context, tuple(devices))


def select_devices(devices: Sequence[Neighbor], query: DeviceQuery) -> list[Neighbor]:
    filtered = filter_devices(
        devices,
        device_type=query.device_type,
        status=query.status,
        vendor=query.vendor,
        text=query.text,
    )
    return sort_devices(filtered, query.sort)


def diff_devices(
    previous: dict[str, Neighbor], current: dict[str, Neighbor]
) -> list[tuple[str, Neighbor]]:
    events: list[tuple[str, Neighbor]] = []
    events.extend(("NEW", current[key]) for key in sorted(current.keys() - previous.keys()))
    events.extend(("OFFLINE", previous[key]) for key in sorted(previous.keys() - current.keys()))
    for key in sorted(current.keys() & previous.keys()):
        before, after = previous[key], current[key]
        if before.responsive != after.responsive:
            events.append(("ONLINE" if after.responsive else "OFFLINE", after))
        elif (before.ip, before.hostname, before.vendor, before.model, before.services) != (
            after.ip,
            after.hostname,
            after.vendor,
            after.model,
            after.services,
        ):
            events.append(("CHANGED", after))
    return events


def keyed_devices(devices: Sequence[Neighbor]) -> dict[str, Neighbor]:
    return {device_key(device): device for device in devices}

