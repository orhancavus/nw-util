import tempfile
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from unittest.mock import patch

from nw_util.models import Neighbor, NetworkContext
from nw_util.services.scanner import DeviceQuery, ScanOptions, collect_devices, select_devices
from nw_util.storage import DeviceStore


class ScannerServiceTests(unittest.TestCase):
    def test_scan_phases_and_history_are_shared(self) -> None:
        context = NetworkContext(
            IPv4Address("192.168.1.2"),
            IPv4Network("192.168.1.0/24"),
            "en0",
            IPv4Address("192.168.1.1"),
        )
        device = Neighbor(IPv4Address("192.168.1.2"), hostname="console", is_self=True)
        phases: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceStore(Path(directory) / "state.json")
            with patch("nw_util.services.scanner.detect_network", return_value=context), patch(
                "nw_util.services.scanner.scan", return_value=[device]
            ):
                result = collect_devices(ScanOptions(), store, progress=phases.append)
            self.assertEqual(result.context, context)
            self.assertEqual(result.devices, (device,))
            self.assertEqual(phases, ["detecting_network", "probing_hosts", "saving_history", "complete"])
            self.assertEqual(len(store.history()), 1)

    def test_query_is_framework_neutral(self) -> None:
        devices = [
            Neighbor(IPv4Address("192.168.1.20"), hostname="printer", latency_ms=2),
            Neighbor(IPv4Address("192.168.1.2"), hostname="laptop", latency_ms=1),
        ]
        selected = select_devices(devices, DeviceQuery(text="lap", sort="latency"))
        self.assertEqual([str(device.ip) for device in selected], ["192.168.1.2"])


if __name__ == "__main__":
    unittest.main()
