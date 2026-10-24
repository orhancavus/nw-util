from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network


@dataclass(frozen=True, slots=True)
class NetworkContext:
    address: IPv4Address
    network: IPv4Network
    interface: str | None = None
    gateway: IPv4Address | None = None


@dataclass(frozen=True, slots=True)
class Neighbor:
    ip: IPv4Address
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    services: tuple[str, ...] = ()
    alias: str | None = None
    latency_ms: float | None = None
    neighbor_state: str | None = None
    responsive: bool = True
    is_self: bool = False
    is_gateway: bool = False


@dataclass(frozen=True, slots=True)
class DevicePresentation:
    emoji: str
    device_type: str
    name: str
    status: str

