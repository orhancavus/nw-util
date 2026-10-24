from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import replace
from typing import Sequence

from .models import Neighbor


COMMON_PORTS = (
    22, 23, 53, 80, 81, 139, 443, 445, 515, 548, 554, 631, 1883,
    5000, 5001, 7000, 8008, 8009, 8060, 8123, 8883, 9100, 32400,
)


def _resolve_name(ip: ipaddress.IPv4Address) -> str | None:
    if platform.system() == "Darwin":
        args = ("dscacheutil", "-q", "host", "-a", "ip_address", str(ip))
        pattern = r"^name:\s*(\S+)"
    else:
        args = ("getent", "hosts", str(ip))
        pattern = rf"^{re.escape(str(ip))}\s+(\S+)"
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=1.5, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    match = re.search(pattern, result.stdout, re.MULTILINE)
    return match.group(1).removesuffix(".") if match else None


def parse_nmap_services(xml_output: str) -> dict[ipaddress.IPv4Address, tuple[str, ...]]:
    found: dict[ipaddress.IPv4Address, tuple[str, ...]] = {}
    if not xml_output.strip():
        return found
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return found
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None or not address.get("addr"):
            continue
        services: list[str] = []
        for port in host.findall("./ports/port"):
            if (state := port.find("state")) is None or state.get("state") != "open":
                continue
            service = port.find("service")
            port_id = port.get("portid", "?")
            name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            description = " ".join(value for value in (product, version) if value)
            services.append(f"{port_id}/{name}" + (f" ({description})" if description else ""))
        try:
            found[ipaddress.IPv4Address(address.get("addr"))] = tuple(services)
        except ipaddress.AddressValueError:
            continue
    return found


def _nmap_services(devices: Sequence[Neighbor], timeout: float) -> dict[ipaddress.IPv4Address, tuple[str, ...]]:
    if not devices or shutil.which("nmap") is None:
        return {}
    args = [
        "nmap", "-sT", "-sV", "--version-light", "-T4", "-Pn",
        "--host-timeout", "8s", "-p", ",".join(map(str, COMMON_PORTS)),
        "-oX", "-", *[str(device.ip) for device in devices],
    ]
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=max(15.0, len(devices) * timeout * 8),
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    return parse_nmap_services(result.stdout)


def enrich_devices(
    devices: Sequence[Neighbor], *, timeout: float = 0.5, workers: int = 32
) -> list[Neighbor]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, max(1, len(devices)))) as pool:
        names = dict(zip((device.ip for device in devices), pool.map(lambda item: _resolve_name(item.ip), devices)))
    services = _nmap_services(devices, timeout)
    return [
        replace(
            device,
            hostname=device.hostname or names.get(device.ip),
            services=services.get(device.ip, ()),
        )
        for device in devices
    ]
