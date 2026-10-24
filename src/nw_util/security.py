from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Any, Sequence

from .enrich import COMMON_PORTS
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
class ServiceProfile:
    port: int
    protocol: str
    name: str
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    confidence: int | None = None
    cpes: tuple[str, ...] = ()

    @property
    def description(self) -> str:
        detail = " ".join(filter(None, (self.product, self.version, self.extra_info)))
        return f"{self.port}/{self.name}" + (f" ({detail})" if detail else "")


@dataclass(frozen=True, slots=True)
class OSGuess:
    name: str
    accuracy: int | None = None
    vendor: str | None = None
    family: str | None = None
    generation: str | None = None
    device_type: str | None = None
    cpes: tuple[str, ...] = ()
    source: str = "service evidence"


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    message: str


@dataclass(frozen=True, slots=True)
class SecurityProfile:
    ip: ipaddress.IPv4Address
    services: tuple[ServiceProfile, ...]
    os_guesses: tuple[OSGuess, ...]
    findings: tuple[Finding, ...]
    scanner: str
    os_detection_note: str | None = None


def _parse_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def parse_security_xml(
    xml_output: str, target: ipaddress.IPv4Address
) -> tuple[tuple[ServiceProfile, ...], tuple[OSGuess, ...]]:
    if not xml_output.strip():
        return (), ()
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return (), ()
    host = next(
        (
            candidate
            for candidate in root.findall("host")
            if (address := candidate.find("address[@addrtype='ipv4']")) is not None
            and address.get("addr") == str(target)
        ),
        None,
    )
    if host is None:
        return (), ()

    services: list[ServiceProfile] = []
    service_os: list[OSGuess] = []
    for port_node in host.findall("./ports/port"):
        state = port_node.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_node.find("service")
        attributes = service.attrib if service is not None else {}
        cpes = tuple(node.text for node in service.findall("cpe") if node.text) if service is not None else ()
        profile = ServiceProfile(
            port=int(port_node.get("portid", "0")),
            protocol=port_node.get("protocol", "tcp"),
            name=attributes.get("name", "unknown"),
            product=attributes.get("product"),
            version=attributes.get("version"),
            extra_info=attributes.get("extrainfo"),
            confidence=_parse_int(attributes.get("conf")),
            cpes=cpes,
        )
        services.append(profile)
        os_name = attributes.get("ostype")
        os_cpes = tuple(cpe for cpe in cpes if cpe.startswith("cpe:/o:"))
        if os_name or os_cpes:
            service_os.append(
                OSGuess(
                    name=os_name or os_cpes[0].removeprefix("cpe:/o:").replace(":", " "),
                    # Nmap's service confidence describes the service match,
                    # not the certainty of an OS inferred from that banner.
                    accuracy=None,
                    family=os_name,
                    cpes=os_cpes,
                    source=f"service evidence on {profile.port}/{profile.protocol}",
                )
            )

    fingerprint_os: list[OSGuess] = []
    for match in host.findall("./os/osmatch")[:3]:
        os_class = match.find("osclass")
        attributes = os_class.attrib if os_class is not None else {}
        cpes = tuple(node.text for node in match.findall("./osclass/cpe") if node.text)
        fingerprint_os.append(
            OSGuess(
                name=match.get("name", "Unknown OS"),
                accuracy=_parse_int(match.get("accuracy")),
                vendor=attributes.get("vendor"),
                family=attributes.get("osfamily"),
                generation=attributes.get("osgen"),
                device_type=attributes.get("type"),
                cpes=cpes,
                source="Nmap TCP/IP fingerprint",
            )
        )

    os_guesses: list[OSGuess] = []
    seen: set[tuple[str, str]] = set()
    for guess in (*fingerprint_os, *service_os):
        key = (guess.name.lower(), guess.source.split(" on ", 1)[0])
        if key not in seen:
            seen.add(key)
            os_guesses.append(guess)
    return tuple(services), tuple(os_guesses)


def _ports_from_services(services: Sequence[ServiceProfile | str]) -> set[int]:
    result: set[int] = set()
    for service in services:
        if isinstance(service, ServiceProfile):
            result.add(service.port)
            continue
        match = re.match(r"(\d+)/", service)
        if match:
            result.add(int(match.group(1)))
    return result


def findings_for(services: Sequence[ServiceProfile | str]) -> tuple[Finding, ...]:
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


def _socket_scan(ip: ipaddress.IPv4Address, timeout: float) -> tuple[ServiceProfile, ...]:
    open_ports: list[ServiceProfile] = []
    for port in INSPECTION_PORTS:
        try:
            with socket.create_connection((str(ip), port), timeout=min(timeout, 0.25)):
                open_ports.append(ServiceProfile(port, "tcp", "unknown"))
        except OSError:
            continue
    return tuple(open_ports)


def _is_privileged() -> bool:
    get_effective_uid = getattr(os, "geteuid", None)
    return bool(get_effective_uid and get_effective_uid() == 0)


def _nmap_profile(
    ip: ipaddress.IPv4Address, timeout: float, os_detect: bool
) -> tuple[tuple[ServiceProfile, ...], tuple[OSGuess, ...], str | None]:
    privileged = _is_privileged()
    note = None
    args = [
        "nmap", "-sT", "-sV", "--version-light", "-T4", "-Pn",
        "--host-timeout", "20s", "-p", ",".join(map(str, INSPECTION_PORTS)),
    ]
    if os_detect and privileged:
        args.extend(("-O", "--osscan-limit", "--osscan-guess", "--max-os-tries", "1"))
    elif os_detect:
        note = "Full TCP/IP OS fingerprinting was skipped because Nmap requires root privileges for -O."
    args.extend(("-oX", "-", str(ip)))
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=max(25.0, timeout * 20),
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return (), (), note
    services, os_guesses = parse_security_xml(result.stdout, ip)
    return services, os_guesses, note


def inspect_ip(
    ip: ipaddress.IPv4Address, timeout: float = 1.0, *, os_detect: bool = False
) -> SecurityProfile:
    if shutil.which("nmap"):
        services, os_guesses, note = _nmap_profile(ip, timeout, os_detect)
        scanner = "Nmap service detection" + (" + OS fingerprinting" if os_detect and _is_privileged() else "")
    else:
        services = _socket_scan(ip, timeout)
        os_guesses = ()
        note = "Install Nmap to identify service versions, CPEs, and probable operating systems."
        scanner = "TCP connect fallback"
    return SecurityProfile(ip, services, os_guesses, findings_for(services), scanner, note)


def profile_as_dict(profile: SecurityProfile) -> dict[str, Any]:
    return {
        "ip": str(profile.ip),
        "scanner": profile.scanner,
        "services": [asdict(service) for service in profile.services],
        "probable_operating_systems": [asdict(guess) for guess in profile.os_guesses],
        "findings": [asdict(finding) for finding in profile.findings],
        "os_detection_note": profile.os_detection_note,
    }


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
