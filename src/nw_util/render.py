from __future__ import annotations

import json
import csv
import io
import re
import unicodedata
from collections.abc import Sequence

from .classify import present
from .models import Neighbor, NetworkContext


RESET = "\033[0m"
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def _paint(value: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{value}{RESET}" if enabled else value


def _display_width(value: str) -> int:
    plain = ANSI_PATTERN.sub("", value)
    return sum(
        0 if unicodedata.combining(char) or unicodedata.category(char) in {"Cf", "Mn"}
        else 2 if unicodedata.east_asian_width(char) in {"W", "F"}
        else 1
        for char in plain
    )


def _pad(value: str, width: int) -> str:
    return value + " " * max(0, width - _display_width(value))


def _clip(value: str, width: int) -> str:
    if _display_width(value) <= width:
        return value
    result = ""
    for char in value:
        if _display_width(result + char + "…") > width:
            break
        result += char
    return result + "…"


def _row(values: Sequence[str], widths: Sequence[int]) -> str:
    return "│ " + " │ ".join(_pad(_clip(value, width), width) for value, width in zip(values, widths)) + " │"


def render_table(devices: Sequence[Neighbor], context: NetworkContext, *, color: bool = True) -> str:
    # Defensively key by IP even though the scanner itself already uses a set.
    devices = list({device.ip: device for device in devices}.values())
    show_services = any(device.services for device in devices)
    header = ["TYPE", "NAME / MODEL", "STATUS", "IP ADDRESS", "MAC ADDRESS", "VENDOR"]
    if show_services:
        header.append("SERVICES")
    rows: list[list[str]] = []
    for device in devices:
        item = present(device)
        if item.status.startswith(("Online", "Reachable")):
            status_code = "1;32"
        elif item.status == "This device":
            status_code = "1;36"
        elif item.status in {"Unreachable"}:
            status_code = "1;31"
        elif item.status in {"Discovered", "Seen recently"}:
            status_code = "33"
        else:
            status_code = "37"
        row = [
                f"{item.emoji}  {item.device_type}",
                item.name,
                _paint(item.status, status_code, color),
                _paint(str(device.ip), "36", color),
                device.mac or "—",
                device.vendor or "—",
            ]
        if show_services:
            row.append(", ".join(device.services) or "—")
        rows.append(row)

    max_widths = (22, 30, 18, 15, 17, 28, 42)
    widths = [
        min(max_widths[index], max([_display_width(value), *(_display_width(row[index]) for row in rows)]))
        for index, value in enumerate(header)
    ]
    top = "╭─" + "─┬─".join("─" * width for width in widths) + "─╮"
    divider = "├─" + "─┼─".join("─" * width for width in widths) + "─┤"
    bottom = "╰─" + "─┴─".join("─" * width for width in widths) + "─╯"
    title = _paint("Local network", "1", color) + " " + _paint(str(context.network), "36", color)
    if context.interface:
        title += "  " + _paint(f"via {context.interface}", "2", color)
    output = ["", title, top, _row([_paint(value, "1", color) for value in header], widths), divider]
    output.extend(_row(row, widths) for row in rows)
    output.extend([bottom, _paint(f"{len(devices)} device{'s' if len(devices) != 1 else ''} found", "2", color), ""])
    return "\n".join(output)


def render_json(devices: Sequence[Neighbor]) -> str:
    rows = []
    for device in {device.ip: device for device in devices}.values():
        item = present(device)
        rows.append(
            {
                "type": item.device_type,
                "name": item.name,
                "status": item.status,
                "ip": str(device.ip),
                "mac": device.mac,
                "vendor": device.vendor,
                "model": device.model,
                "alias": device.alias,
                "latency_ms": device.latency_ms,
                "neighbor_state": device.neighbor_state,
                "services": list(device.services),
                "is_gateway": device.is_gateway,
                "is_self": device.is_self,
            }
        )
    return json.dumps(rows, indent=2)


def render_csv(devices: Sequence[Neighbor]) -> str:
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("type", "name", "status", "ip", "mac", "vendor", "model", "latency_ms", "services"))
    for device in {device.ip: device for device in devices}.values():
        item = present(device)
        writer.writerow(
            (
                item.device_type,
                item.name,
                item.status,
                str(device.ip),
                device.mac or "",
                device.vendor or "",
                device.model or "",
                "" if device.latency_ms is None else f"{device.latency_ms:.3f}",
                "; ".join(device.services),
            )
        )
    return output.getvalue().rstrip("\n")

