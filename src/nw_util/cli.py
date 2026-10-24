from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .enrich import enrich_devices
from .network import detect_network, scan
from .render import render_json, render_table


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nw-util",
        description="Scan the local IPv4 network and display connected devices.",
    )
    parser.add_argument("-n", "--network", metavar="CIDR", help="network to scan, e.g. 192.168.1.0/24")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="ping timeout in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=64, help="maximum concurrent probes (default: 64)")
    parser.add_argument("--max-hosts", type=int, default=1024, help="safety limit for hosts scanned (default: 1024)")
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="resolve local names and identify common services with Nmap when available",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0 or args.workers <= 0 or args.max_hosts <= 0:
        build_parser().error("--timeout, --workers, and --max-hosts must be positive")

    color = (
        not args.no_color
        and os.environ.get("NO_COLOR") is None
        and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") is not None)
    )
    try:
        context = detect_network(args.network)
        if not args.json:
            mode = " with deep enrichment" if args.deep else ""
            print(f"Scanning {context.network}{mode} …", file=sys.stderr)
        devices = scan(context, timeout=args.timeout, workers=args.workers, max_hosts=args.max_hosts)
        if args.deep:
            devices = enrich_devices(devices, timeout=args.timeout, workers=args.workers)
        if args.json:
            print(render_json(devices))
        else:
            print(render_table(devices, context, color=color))
    except (RuntimeError, ValueError) as exc:
        label = f"\033[1;31mError:\033[0m" if color else "Error:"
        print(f"{label} {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        raise SystemExit(130) from None


if __name__ == "__main__":
    main(sys.argv[1:])

