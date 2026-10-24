from __future__ import annotations

from typing import Any

from ..classify import present
from ..models import Neighbor, NetworkContext


def context_dict(context: NetworkContext) -> dict[str, Any]:
    return {
        "address": str(context.address),
        "network": str(context.network),
        "interface": context.interface,
        "gateway": str(context.gateway) if context.gateway else None,
    }


def device_dict(device: Neighbor) -> dict[str, Any]:
    item = present(device)
    return {
        "id": f"mac:{device.mac.lower()}" if device.mac else f"ip:{device.ip}",
        "type": item.device_type,
        "emoji": item.emoji,
        "name": item.name,
        "status": item.status,
        "ip": str(device.ip),
        "mac": device.mac,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "model": device.model,
        "services": list(device.services),
        "alias": device.alias,
        "latency_ms": device.latency_ms,
        "neighbor_state": device.neighbor_state,
        "responsive": device.responsive,
        "is_self": device.is_self,
        "is_gateway": device.is_gateway,
    }

