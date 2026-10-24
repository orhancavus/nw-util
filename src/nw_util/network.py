from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import math
import platform
import re
import socket
import subprocess
from pathlib import Path

from .models import Neighbor, NetworkContext


MAC_PATTERN = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
INVALID_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def _run(*args: str, timeout: float = 3.0) -> str:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


def _fallback_address() -> ipaddress.IPv4Address:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 53))
        return ipaddress.IPv4Address(sock.getsockname()[0])
    except OSError:
        try:
            return ipaddress.IPv4Address(socket.gethostbyname(socket.gethostname()))
        except (OSError, ipaddress.AddressValueError) as exc:
            raise RuntimeError("Could not determine this device's LAN address") from exc
    finally:
        sock.close()


def _linux_context() -> NetworkContext | None:
    routes = _run("ip", "-j", "route", "show", "default")
    if not routes:
        return None
    try:
        route = json.loads(routes)[0]
        interface = route.get("dev")
        gateway = ipaddress.IPv4Address(route["gateway"]) if route.get("gateway") else None
        addresses = json.loads(_run("ip", "-j", "address", "show", "dev", interface))
        info = next(item for item in addresses[0]["addr_info"] if item["family"] == "inet")
        address = ipaddress.IPv4Address(info["local"])
        network = ipaddress.IPv4Network(f"{address}/{info['prefixlen']}", strict=False)
        return NetworkContext(address, network, interface, gateway)
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _darwin_context() -> NetworkContext | None:
    route = _run("route", "-n", "get", "default")
    interface_match = re.search(r"^\s*interface:\s*(\S+)", route, re.MULTILINE)
    gateway_match = re.search(r"^\s*gateway:\s*(\d+(?:\.\d+){3})", route, re.MULTILINE)
    if not interface_match:
        # Sandboxed macOS processes may be denied the routing socket used by
        # `route`, while the read-only routing table remains available.
        route = _run("netstat", "-rn", "-f", "inet")
        default_match = re.search(
            r"^default\s+(\d+(?:\.\d+){3})\s+\S+\s+(\S+)", route, re.MULTILINE
        )
        if default_match:
            gateway_match = default_match
            interface_match = re.match(r"(\S+)", default_match.group(2))
    if not interface_match:
        return None
    interface = interface_match.group(1)
    raw_address = _run("ipconfig", "getifaddr", interface).strip()
    config = _run("ifconfig", interface)
    if not raw_address:
        address_match = re.search(r"^\s*inet\s+(\d+(?:\.\d+){3})\s", config, re.MULTILINE)
        raw_address = address_match.group(1) if address_match else ""
    if not raw_address:
        return None
    mask_match = re.search(r"inet\s+" + re.escape(raw_address) + r"\s+netmask\s+(0x[0-9a-fA-F]+)", config)
    if not mask_match:
        return None
    mask_int = int(mask_match.group(1), 16)
    prefix = bin(mask_int).count("1")
    address = ipaddress.IPv4Address(raw_address)
    gateway = ipaddress.IPv4Address(gateway_match.group(1)) if gateway_match else None
    return NetworkContext(address, ipaddress.IPv4Network(f"{address}/{prefix}", strict=False), interface, gateway)


def detect_network(network_override: str | None = None) -> NetworkContext:
    system = platform.system()
    context = _linux_context() if system == "Linux" else _darwin_context() if system == "Darwin" else None
    if context is None:
        address = _fallback_address()
        context = NetworkContext(address, ipaddress.IPv4Network(f"{address}/24", strict=False))

    if network_override:
        try:
            network = ipaddress.IPv4Network(network_override, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 network: {network_override}") from exc
        context = NetworkContext(context.address, network, context.interface, context.gateway)
    return context


def _ping(ip: ipaddress.IPv4Address, timeout: float) -> bool:
    milliseconds = max(100, int(timeout * 1000))
    system = platform.system()
    if system == "Windows":
        args = ("ping", "-n", "1", "-w", str(milliseconds), str(ip))
    elif system == "Darwin":
        args = ("ping", "-n", "-c", "1", "-W", str(milliseconds), str(ip))
    else:
        args = ("ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), str(ip))
    try:
        return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def ping_sweep(network: ipaddress.IPv4Network, *, timeout: float = 0.5, workers: int = 64) -> set[ipaddress.IPv4Address]:
    hosts = list(network.hosts())
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, max(1, len(hosts)))) as pool:
        results = pool.map(lambda ip: (ip, _ping(ip, timeout)), hosts)
        return {ip for ip, alive in results if alive}


def _normalize_mac(value: str) -> str | None:
    value = value.lower()
    if value in INVALID_MACS:
        return None
    return value.upper()


def read_neighbors() -> dict[ipaddress.IPv4Address, tuple[str, str | None]]:
    neighbors: dict[ipaddress.IPv4Address, tuple[str, str | None]] = {}
    ip_output = _run("ip", "neigh", "show")
    for line in ip_output.splitlines():
        match = re.search(rf"^(\d+(?:\.\d+){{3}}).*?\blladdr\s+({MAC_PATTERN})\b", line)
        if match and (mac := _normalize_mac(match.group(2))):
            try:
                neighbors[ipaddress.IPv4Address(match.group(1))] = (mac, None)
            except ipaddress.AddressValueError:
                pass

    arp_output = _run("arp", "-an") or _run("arp", "-a")
    for line in arp_output.splitlines():
        match = re.search(rf"^(\S+)\s+\((\d+(?:\.\d+){{3}})\)\s+at\s+({MAC_PATTERN})", line)
        if not match:
            match = re.search(rf"^\s*(\d+(?:\.\d+){{3}})\s+({MAC_PATTERN})", line)
            if match:
                hostname, raw_ip, raw_mac = None, match.group(1), match.group(2)
            else:
                continue
        else:
            raw_name, raw_ip, raw_mac = match.groups()
            hostname = None if raw_name in {"?", raw_ip} else raw_name.removesuffix(".")
        if mac := _normalize_mac(raw_mac):
            try:
                ip = ipaddress.IPv4Address(raw_ip)
                previous = neighbors.get(ip)
                neighbors[ip] = (mac, hostname or (previous[1] if previous else None))
            except ipaddress.AddressValueError:
                pass
    return neighbors


def _read_oui_database() -> dict[str, str]:
    candidates = (
        Path("/opt/homebrew/share/nmap/nmap-mac-prefixes"),
        Path("/usr/local/share/nmap/nmap-mac-prefixes"),
        Path("/usr/share/ieee-data/oui.txt"),
        Path("/usr/share/misc/oui.txt"),
        Path("/var/lib/ieee-data/oui.txt"),
    )
    database: dict[str, str] = {}
    for path in candidates:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            match = re.match(r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+?)\s*$", line)
            if not match:
                match = re.match(r"^([0-9A-Fa-f]{6})\s+(.+?)\s*$", line)
            if match:
                database[match.group(1).upper()] = match.group(2)
        if database:
            break
    return database


def _vendor_for(mac: str | None, database: dict[str, str]) -> str | None:
    if not mac:
        return None
    first_octet = int(mac[:2], 16)
    if first_octet & 0b10:
        return "Private / randomized MAC"
    return database.get(mac.replace(":", "")[:6])


def scan(
    context: NetworkContext,
    *,
    timeout: float = 0.5,
    workers: int = 64,
    max_hosts: int = 1024,
) -> list[Neighbor]:
    host_count = max(0, context.network.num_addresses - 2)
    if host_count > max_hosts:
        raise ValueError(
            f"{context.network} contains {host_count:,} hosts; use a narrower network or increase --max-hosts"
        )

    alive = ping_sweep(context.network, timeout=timeout, workers=workers)
    if context.address in context.network:
        alive.add(context.address)
    cached = read_neighbors()
    relevant_cached = {ip for ip in cached if ip in context.network}
    discovered = alive | relevant_cached
    if context.gateway and context.gateway in context.network:
        discovered.add(context.gateway)

    vendors = _read_oui_database()
    hostname = socket.gethostname().removesuffix(".")
    devices: list[Neighbor] = []
    for ip in sorted(discovered):
        mac, cached_name = cached.get(ip, (None, None))
        is_self = ip == context.address
        devices.append(
            Neighbor(
                ip=ip,
                mac=mac,
                hostname=hostname if is_self else cached_name,
                vendor=_vendor_for(mac, vendors),
                responsive=ip in alive,
                is_self=is_self,
                is_gateway=ip == context.gateway,
            )
        )
    return devices

