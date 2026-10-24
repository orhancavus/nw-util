from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
from datetime import datetime

from . import __version__
from .models import Neighbor, NetworkContext
from .network import detect_network
from .render import render_csv, render_json, render_table
from .security import inspect_ip, profile_as_dict, resolve_target
from .services.scanner import (
    DeviceQuery,
    ScanOptions,
    collect_devices as collect_scan_devices,
    diff_devices,
    keyed_devices,
    select_devices,
)
from .storage import DeviceStore


def _add_scan_arguments(parser: argparse.ArgumentParser, *, output: bool = True) -> None:
    parser.add_argument("-n", "--network", metavar="CIDR", help="network to scan, e.g. 192.168.1.0/24")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="ping timeout in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=64, help="maximum concurrent probes (default: 64)")
    parser.add_argument("--max-hosts", type=int, default=1024, help="safety limit for hosts scanned (default: 1024)")
    parser.add_argument("--deep", action="store_true", help="resolve names and identify common services with Nmap")
    parser.add_argument("--discover", action="store_true", help="discover devices and services using mDNS/DNS-SD")
    parser.add_argument("--mdns-timeout", type=float, default=2.0, help="mDNS discovery window in seconds (default: 2)")
    parser.add_argument("--no-history", action="store_true", help="do not update persistent device history")
    if output:
        parser.add_argument("--format", choices=("table", "json", "csv"), default="table", help="output format")
        parser.add_argument("--json", action="store_true", help="shortcut for --format json")
        parser.add_argument("--type", dest="device_type", help="only show matching device types")
        parser.add_argument("--status", help="only show matching statuses")
        parser.add_argument("--vendor", help="only show matching vendors")
        parser.add_argument("--filter", dest="text_filter", help="search all displayed device fields")
        parser.add_argument(
            "--sort",
            choices=("ip", "name", "type", "status", "vendor", "latency"),
            default="ip",
            help="sort result rows (default: ip)",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nw-util",
        description="Scan, identify, and monitor devices on the local IPv4 network.",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _add_scan_arguments(parser)
    commands = parser.add_subparsers(dest="command")

    alias = commands.add_parser("alias", help="assign a persistent name to an IP, MAC, or hostname")
    alias.add_argument("target")
    alias.add_argument("name")

    unalias = commands.add_parser("unalias", help="remove a persistent alias")
    unalias.add_argument("target")

    history = commands.add_parser("history", help="show previously seen devices")
    history.add_argument("target", nargs="?")
    history.add_argument("--json", action="store_true")

    watch = commands.add_parser("watch", help="continuously report device changes")
    _add_scan_arguments(watch, output=False)
    watch.add_argument("--interval", type=float, default=10.0, help="seconds between scans (default: 10)")
    watch.add_argument("--count", type=int, default=0, help="stop after this many scans; 0 watches forever")

    security = commands.add_parser(
        "security",
        aliases=("inspect",),
        help="build a security profile for one device (alias: inspect)",
    )
    security.add_argument("target", help="IP address, MAC address, hostname, or saved alias")
    security.add_argument(
        "--os-detect",
        action="store_true",
        help="request privileged Nmap TCP/IP OS fingerprinting when already running as root",
    )
    security.add_argument("--json", action="store_true", help="output the complete profile as JSON")
    _add_scan_arguments(security, output=False)

    web = commands.add_parser("web", help="start the local web operator console")
    web.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    web.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    web.add_argument("--reload", action="store_true", help="reload the server when source files change")
    return parser


def _color_enabled(args: argparse.Namespace) -> bool:
    return (
        not getattr(args, "no_color", False)
        and os.environ.get("NO_COLOR") is None
        and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") is not None)
    )


def _validate_scan_args(args: argparse.Namespace) -> None:
    _scan_options(args).validate()


def _scan_options(args: argparse.Namespace) -> ScanOptions:
    return ScanOptions(
        network=args.network,
        timeout=args.timeout,
        workers=args.workers,
        max_hosts=args.max_hosts,
        deep=args.deep,
        discover=args.discover,
        mdns_timeout=args.mdns_timeout,
        record_history=not args.no_history,
    )


def collect_devices(
    args: argparse.Namespace,
    store: DeviceStore,
    *,
    announce: bool = True,
) -> tuple[NetworkContext, list[Neighbor]]:
    options = _scan_options(args)
    options.validate()
    context = detect_network(options.network)
    if announce:
        modes = []
        if args.discover or args.deep:
            modes.append("mDNS")
        if args.deep:
            modes.append("service")
        suffix = f" with {' + '.join(modes)} enrichment" if modes else ""
        print(f"Scanning {context.network}{suffix} …", file=sys.stderr)
    result = collect_scan_devices(options, store, context=context)
    return result.context, list(result.devices)


def _selected_devices(args: argparse.Namespace, devices: list[Neighbor]) -> list[Neighbor]:
    return select_devices(
        devices,
        DeviceQuery(
        device_type=args.device_type,
        status=args.status,
        vendor=args.vendor,
        text=args.text_filter,
            sort=args.sort,
        ),
    )


def _run_scan(args: argparse.Namespace, store: DeviceStore, color: bool) -> None:
    context, devices = collect_devices(args, store)
    devices = _selected_devices(args, devices)
    output_format = "json" if args.json else args.format
    if output_format == "json":
        print(render_json(devices))
    elif output_format == "csv":
        print(render_csv(devices))
    else:
        print(render_table(devices, context, color=color))


def _run_history(args: argparse.Namespace, store: DeviceStore) -> None:
    records = store.history(args.target)
    if args.json:
        print(json.dumps(records, indent=2))
        return
    if not records:
        print("No matching device history.")
        return
    for record in records:
        name = record.get("alias") or record.get("hostname") or record.get("model") or "Unknown"
        addresses = ", ".join(record.get("ips", []))
        raw_last_seen = record.get("last_seen")
        try:
            last_seen = datetime.fromisoformat(raw_last_seen).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        except (TypeError, ValueError):
            last_seen = raw_last_seen or "—"
        print(f"{name}  {addresses}  {record.get('type', 'Unknown')}  last seen {last_seen}")


def _event(kind: str, device: Neighbor) -> str:
    timestamp = datetime.now().strftime("%H:%M:%S")
    icons = {"NEW": "🟢", "ONLINE": "🟢", "OFFLINE": "🔴", "CHANGED": "🟡"}
    name = device.alias or device.hostname or device.model or device.vendor or "Unknown"
    return f"{timestamp}  {icons[kind]} {kind:<7}  {name:<28} {device.ip}"


def _run_watch(args: argparse.Namespace, store: DeviceStore, color: bool) -> None:
    if args.interval <= 0 or args.count < 0:
        raise ValueError("--interval must be positive and --count cannot be negative")
    previous: dict[str, Neighbor] = {}
    iteration = 0
    while args.count == 0 or iteration < args.count:
        context, devices = collect_devices(args, store, announce=iteration == 0)
        current = keyed_devices(devices)
        if iteration == 0:
            print(render_table(devices, context, color=color))
            print(f"Watching every {args.interval:g} seconds. Press Ctrl-C to stop.")
        else:
            for kind, device in diff_devices(previous, current):
                print(_event(kind, device), flush=True)
        previous = current
        iteration += 1
        if args.count == 0 or iteration < args.count:
            time.sleep(args.interval)


def _history_target_ip(target: str, store: DeviceStore) -> str | None:
    records = store.history(target)
    if not records or not records[0].get("ips"):
        return None
    return records[0]["ips"][-1]


def _run_web(args: argparse.Namespace) -> None:
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            "Warning: the web UI is being exposed beyond this computer and reveals local network metadata.",
            file=sys.stderr,
        )
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("Web dependencies are not installed; reinstall nw-util to enable the web UI") from exc
    print(f"Starting nw-util web UI at http://{args.host}:{args.port}", file=sys.stderr)
    uvicorn.run("nw_util.api.app:create_app", host=args.host, port=args.port, reload=args.reload, factory=True)


def _run_inspect(args: argparse.Namespace, store: DeviceStore) -> None:
    try:
        ip = ipaddress.IPv4Address(args.target)
        devices: list[Neighbor] = []
    except ipaddress.AddressValueError:
        _, devices = collect_devices(args, store)
        ip = resolve_target(args.target, devices)
    if ip is None and (historical_ip := _history_target_ip(args.target, store)):
        ip = ipaddress.IPv4Address(historical_ip)
    if ip is None:
        raise ValueError(f"Could not resolve device target: {args.target}")
    result = inspect_ip(ip, timeout=args.timeout, os_detect=args.os_detect)
    if args.json:
        print(json.dumps(profile_as_dict(result), indent=2))
        return
    print(f"\nSecurity profile: {ip}")
    print(f"Scanner: {result.scanner}")
    if result.os_detection_note:
        print(f"Note: {result.os_detection_note}")
    if result.os_guesses:
        print("\nProbable operating system:")
        for guess in result.os_guesses:
            confidence = f" · {guess.accuracy}% confidence" if guess.accuracy is not None else ""
            device_type = f" · {guess.device_type}" if guess.device_type else ""
            print(f"  • {guess.name}{confidence}{device_type} [{guess.source}]")
            for cpe in guess.cpes:
                print(f"      CPE: {cpe}")
    else:
        print("\nProbable operating system: insufficient evidence")
    if result.services:
        print("\nOpen services:")
        for service in result.services:
            confidence = f" · confidence {service.confidence}/10" if service.confidence is not None else ""
            details = " ".join(filter(None, (service.product, service.version, service.extra_info)))
            detail_text = f" · {details}" if details else ""
            print(f"  • {service.port}/{service.protocol} {service.name}{detail_text}{confidence}")
            for cpe in service.cpes:
                print(f"      CPE: {cpe}")
    else:
        print("\nNo inspected TCP services responded.")
    severity_counts = {
        severity: sum(finding.severity == severity for finding in result.findings)
        for severity in ("high", "medium", "info")
    }
    print(
        "\nRisk summary: "
        f"{severity_counts['high']} high · {severity_counts['medium']} medium · {severity_counts['info']} informational"
    )
    if result.findings:
        print("\nObservations:")
        for finding in result.findings:
            print(f"  [{finding.severity.upper()}] {finding.message}")
    else:
        print("\nNo notable exposure was identified in the inspected port set.")
    print("\nResults are observational and do not prove that a service is secure or vulnerable.")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    color = _color_enabled(args)
    store = DeviceStore()
    try:
        if args.command == "alias":
            store.set_alias(args.target, args.name)
            print(f"Alias saved: {args.target} → {args.name}")
        elif args.command == "unalias":
            if store.remove_alias(args.target):
                print(f"Alias removed: {args.target}")
            else:
                raise ValueError(f"No alias exists for: {args.target}")
        elif args.command == "history":
            _run_history(args, store)
        elif args.command == "watch":
            _run_watch(args, store, color)
        elif args.command in {"security", "inspect"}:
            _run_inspect(args, store)
        elif args.command == "web":
            _run_web(args)
        else:
            _run_scan(args, store, color)
    except (RuntimeError, ValueError, OSError) as exc:
        label = "\033[1;31mError:\033[0m" if color else "Error:"
        print(f"{label} {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        raise SystemExit(130) from None


if __name__ == "__main__":
    main(sys.argv[1:])
