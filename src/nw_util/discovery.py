from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Sequence

from .models import Neighbor, NetworkContext


COMMON_SERVICE_TYPES = (
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_workstation._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_hap._tcp.local.",
    "_home-assistant._tcp.local.",
    "_device-info._tcp.local.",
)


@dataclass(frozen=True, slots=True)
class MdnsRecord:
    ip: ipaddress.IPv4Address
    hostname: str | None = None
    model: str | None = None
    vendor: str | None = None
    services: tuple[str, ...] = ()


def _property(properties: dict[str, str], *keys: str) -> str | None:
    lowered = {str(key).lower(): str(value) for key, value in properties.items()}
    return next((lowered[key] for key in keys if lowered.get(key)), None)


def record_from_service(type_: str, name: str, info: Any) -> list[MdnsRecord]:
    try:
        addresses = info.parsed_addresses()
    except (AttributeError, OSError):
        return []
    properties = getattr(info, "decoded_properties", {}) or {}
    instance = name.removesuffix(type_).rstrip(".")
    hostname = (getattr(info, "server", None) or instance or None)
    if hostname:
        hostname = hostname.removesuffix(".")
    model = _property(properties, "model", "md", "am", "ty", "product")
    vendor = _property(properties, "manufacturer", "vendor", "mf")
    service_name = type_.removesuffix(".local.").lstrip("_").replace("._tcp", "").replace("._udp", "")
    port = getattr(info, "port", None)
    service = f"{service_name}:{port}" if port else service_name
    records: list[MdnsRecord] = []
    for raw_address in addresses:
        try:
            ip = ipaddress.ip_address(raw_address.split("%", 1)[0])
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv4Address):
            records.append(MdnsRecord(ip, hostname, model, vendor, (service,)))
    return records


def _merge_records(records: Sequence[MdnsRecord]) -> dict[ipaddress.IPv4Address, MdnsRecord]:
    merged: dict[ipaddress.IPv4Address, MdnsRecord] = {}
    for record in records:
        previous = merged.get(record.ip)
        if previous is None:
            merged[record.ip] = record
            continue
        merged[record.ip] = MdnsRecord(
            ip=record.ip,
            hostname=previous.hostname or record.hostname,
            model=previous.model or record.model,
            vendor=previous.vendor or record.vendor,
            services=tuple(dict.fromkeys((*previous.services, *record.services))),
        )
    return merged


def discover_mdns(timeout: float = 2.0) -> dict[ipaddress.IPv4Address, MdnsRecord]:
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf, ZeroconfServiceTypes
    except ImportError:
        return {}

    found: list[MdnsRecord] = []
    lock = threading.Lock()

    class Listener(ServiceListener):
        def add_service(self, zc: Any, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name, timeout=1000)
            if info is not None:
                with lock:
                    found.extend(record_from_service(type_, name, info))

        def update_service(self, zc: Any, type_: str, name: str) -> None:
            self.add_service(zc, type_, name)

        def remove_service(self, zc: Any, type_: str, name: str) -> None:
            return None

    try:
        zc = Zeroconf()
    except OSError:
        return {}
    try:
        discovery_window = max(0.5, timeout * 0.35)
        try:
            advertised = ZeroconfServiceTypes.find(zc=zc, timeout=discovery_window)
        except OSError:
            advertised = ()
        service_types = tuple(dict.fromkeys((*COMMON_SERVICE_TYPES, *advertised)))
        try:
            browser = ServiceBrowser(zc, list(service_types), Listener())
            time.sleep(max(0.1, timeout - discovery_window))
            browser.cancel()
        except OSError:
            return _merge_records(found)
    finally:
        zc.close()
    return _merge_records(found)


def merge_mdns(
    devices: Sequence[Neighbor],
    records: dict[ipaddress.IPv4Address, MdnsRecord],
    context: NetworkContext,
) -> list[Neighbor]:
    merged = {device.ip: device for device in devices}
    for ip, record in records.items():
        if ip not in context.network:
            continue
        current = merged.get(ip)
        if current is None:
            merged[ip] = Neighbor(
                ip=ip,
                hostname=record.hostname,
                vendor=record.vendor,
                model=record.model,
                services=record.services,
                responsive=True,
                is_gateway=ip == context.gateway,
                is_self=ip == context.address,
            )
            continue
        merged[ip] = replace(
            current,
            hostname=current.hostname or record.hostname,
            vendor=current.vendor or record.vendor,
            model=current.model or record.model,
            services=tuple(dict.fromkeys((*current.services, *record.services))),
            responsive=True,
        )
    return [merged[ip] for ip in sorted(merged)]
