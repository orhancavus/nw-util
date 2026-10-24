from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .classify import present
from .models import Neighbor


def default_state_path() -> Path:
    override = os.environ.get("NW_UTIL_STATE_PATH")
    if override:
        return Path(override).expanduser()
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "nw-util" / "state.json"


def normalize_target(target: str) -> str:
    compact = target.strip().lower()
    if re.fullmatch(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", compact):
        return compact.replace("-", ":")
    return compact


def device_key(device: Neighbor) -> str:
    return f"mac:{device.mac.lower()}" if device.mac else f"ip:{device.ip}"


class DeviceStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_state_path()
        self._lock = threading.RLock()
        self.data: dict[str, Any] = {"version": 1, "aliases": {}, "devices": {}}
        self.load()

    def load(self) -> None:
        with self._lock:
            try:
                loaded = json.loads(self.path.read_text())
            except (OSError, json.JSONDecodeError, TypeError):
                return
            if isinstance(loaded, dict):
                self.data["aliases"] = loaded.get("aliases", {}) if isinstance(loaded.get("aliases", {}), dict) else {}
                self.data["devices"] = loaded.get("devices", {}) if isinstance(loaded.get("devices", {}), dict) else {}

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(prefix="state-", suffix=".json", dir=self.path.parent)
            try:
                with os.fdopen(descriptor, "w") as handle:
                    json.dump(self.data, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                os.chmod(temporary, 0o600)
                os.replace(temporary, self.path)
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def set_alias(self, target: str, name: str) -> None:
        with self._lock:
            normalized = normalize_target(target)
            clean_name = name.strip()
            if not clean_name:
                raise ValueError("Alias name cannot be empty")
            self.data["aliases"][normalized] = clean_name
            for key, record in self.data["devices"].items():
                values = [key, record.get("hostname"), *record.get("ips", []), *record.get("macs", [])]
                if any(value and normalize_target(str(value).removeprefix("mac:").removeprefix("ip:")) == normalized for value in values):
                    record["alias"] = clean_name
            self.save()

    def remove_alias(self, target: str) -> bool:
        with self._lock:
            normalized = normalize_target(target)
            removed = self.data["aliases"].pop(normalized, None) is not None
            if removed:
                for key, record in self.data["devices"].items():
                    values = [key, record.get("hostname"), *record.get("ips", []), *record.get("macs", [])]
                    if any(
                        value
                        and normalize_target(str(value).removeprefix("mac:").removeprefix("ip:")) == normalized
                        for value in values
                    ):
                        record["alias"] = None
                self.save()
            return removed

    def alias_for(self, device: Neighbor) -> str | None:
        with self._lock:
            aliases = self.data["aliases"]
            candidates = [str(device.ip).lower()]
            if device.mac:
                candidates.insert(0, device.mac.lower())
            if device.hostname:
                candidates.append(device.hostname.lower())
            return next((aliases[key] for key in candidates if key in aliases), None)

    def apply_aliases(self, devices: Sequence[Neighbor]) -> list[Neighbor]:
        return [replace(device, alias=self.alias_for(device)) for device in devices]

    def record(self, devices: Sequence[Neighbor], now: datetime | None = None) -> None:
        with self._lock:
            timestamp = (now or datetime.now(timezone.utc)).isoformat()
            records = self.data["devices"]
            for device in devices:
                key = device_key(device)
                previous = records.get(key)
                if previous is None and device.mac:
                    # Merge an earlier mDNS/IP-only observation once ARP later
                    # reveals the stable MAC, without merging two known MACs that
                    # merely reused the same DHCP address.
                    old_key = next(
                        (
                            candidate_key
                            for candidate_key, candidate in records.items()
                            if not candidate.get("macs") and str(device.ip) in candidate.get("ips", [])
                        ),
                        None,
                    )
                    previous = records.pop(old_key) if old_key else None
                previous = previous or {}
                ips = list(dict.fromkeys([*previous.get("ips", []), str(device.ip)]))
                macs = list(dict.fromkeys([*previous.get("macs", []), *([device.mac] if device.mac else [])]))
                records[key] = {
                    "first_seen": previous.get("first_seen", timestamp),
                    "last_seen": timestamp,
                    "ips": ips[-20:],
                    "macs": macs[-20:],
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "model": device.model,
                    "type": present(device).device_type,
                    "alias": device.alias,
                }
            self.save()

    def history(self, target: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            result: list[dict[str, Any]] = []
            needle = normalize_target(target) if target else None
            for key, record in self.data["devices"].items():
                item = {"id": key, **record}
                searchable = " ".join(
                    str(value)
                    for value in (key, record.get("alias"), record.get("hostname"), *record.get("ips", []), *record.get("macs", []))
                    if value
                ).lower()
                if needle is None or needle in searchable:
                    result.append(item)
            return sorted(result, key=lambda item: item.get("last_seen", ""), reverse=True)
