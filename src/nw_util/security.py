from __future__ import annotations

import ipaddress
import re
import shutil
import socket
from dataclasses import dataclass
from typing import Sequence

from .enrich import COMMON_PORTS, scan_nmap_services
from .models import Neighbor


INSPECTION_PORTS = tuple(
    sorted(
        set(
            (
                20, 21, 23, 25, 110, 143, 389, 636, 1433, 1521, 2049,
                2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
                11211, 27017,
                *COMMON_PORTS,
            )
        )
    )
)


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    message: str


@dataclass(frozen=True, slots=True)
class Inspection:
    ip: ipaddress.IPv4Address
    services: tuple[str, ...]
    findings: tuple[Finding, ...]
    scanner: str


def _ports_from_services(services: Sequence[str]) -> set[int]:
    result: set[int] = set()
    for service in services:
        match = re.match(r"(\d+)/", service)
        if match:
            result.add(int(match.group(1)))
    return result


def findings_for(services: Sequence[str]) -> tuple[Finding, ...]:
    ports = _ports_from_services(services)
    findings: list[Finding] = []
    rules = {
        21: ("medium", "FTP is unencrypted; prefer SFTP or another encrypted transfer protocol."),
        23: ("high", "Telnet is unencrypted and should normally be disabled."),
        2375: ("high", "The Docker API may be exposed without TLS."),
        6379: ("high", "Redis is reachable on the LAN; verify authentication and network binding."),
        9200: ("high", "Elasticsearch is reachable on the LAN; verify authentication and access controls."),
        11211: ("high", "Memcached is reachable on the LAN and should be tightly restricted."),
        27017: ("high", "MongoDB is reachable on the LAN; verify authentication and network binding."),
        3389: ("medium", "Remote Desktop is exposed to the LAN; confirm that this is intentional."),
        5900: ("medium", "VNC is exposed to the LAN; confirm encryption and authentication."),
    }
    for port, (severity, message) in rules.items():
        if port in ports:
            findings.append(Finding(severity, message))
    if 80 in ports and 443 not in ports and 8443 not in ports:
        findings.append(Finding("info", "HTTP is exposed without an observed HTTPS service."))
    if 445 in ports:
        findings.append(Finding("info", "SMB file sharing is reachable on the local network."))
    return tuple(findings)


def _socket_scan(ip: ipaddress.IPv4Address, timeout: float) -> tuple[str, ...]:
    open_ports: list[str] = []
    for port in INSPECTION_PORTS:
        try:
            with socket.create_connection((str(ip), port), timeout=min(timeout, 0.25)):
                open_ports.append(f"{port}/tcp")
        except OSError:
            continue
    return tuple(open_ports)


def inspect_ip(ip: ipaddress.IPv4Address, timeout: float = 1.0) -> Inspection:
    if shutil.which("nmap"):
        services_by_ip = scan_nmap_services([ip], timeout=timeout, ports=INSPECTION_PORTS)
        services = services_by_ip.get(ip, ())
        scanner = "Nmap service detection"
    else:
        services = _socket_scan(ip, timeout)
        scanner = "TCP connect fallback"
    return Inspection(ip, services, findings_for(services), scanner)


def resolve_target(target: str, devices: Sequence[Neighbor]) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(target)
    except ipaddress.AddressValueError:
        pass
    needle = target.lower()
    for device in devices:
        values = (device.mac, device.alias, device.hostname)
        if any(value and value.lower() == needle for value in values):
            return device.ip
    return None
