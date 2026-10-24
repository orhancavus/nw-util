from __future__ import annotations

from collections.abc import Sequence

from .classify import present
from .models import Neighbor


def filter_devices(
    devices: Sequence[Neighbor],
    *,
    device_type: str | None = None,
    status: str | None = None,
    vendor: str | None = None,
    text: str | None = None,
) -> list[Neighbor]:
    result: list[Neighbor] = []
    for device in devices:
        item = present(device)
        haystack = " ".join(
            filter(
                None,
                (
                    item.device_type,
                    item.name,
                    item.status,
                    str(device.ip),
                    device.mac,
                    device.vendor,
                    device.model,
                    *device.services,
                ),
            )
        ).lower()
        if device_type and device_type.lower() not in item.device_type.lower():
            continue
        if status and status.lower() not in item.status.lower():
            continue
        if vendor and vendor.lower() not in (device.vendor or "").lower():
            continue
        if text and text.lower() not in haystack:
            continue
        result.append(device)
    return result


def sort_devices(devices: Sequence[Neighbor], field: str) -> list[Neighbor]:
    if field == "ip":
        key = lambda device: int(device.ip)
    elif field == "name":
        key = lambda device: present(device).name.lower()
    elif field == "type":
        key = lambda device: present(device).device_type.lower()
    elif field == "status":
        key = lambda device: present(device).status.lower()
    elif field == "vendor":
        key = lambda device: (device.vendor or "").lower()
    elif field == "latency":
        key = lambda device: device.latency_ms if device.latency_ms is not None else float("inf")
    else:
        raise ValueError(f"Unsupported sort field: {field}")
    return sorted(devices, key=key)
