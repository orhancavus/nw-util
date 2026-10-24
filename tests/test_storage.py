import tempfile
import unittest
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

from nw_util.models import Neighbor
from nw_util.storage import DeviceStore


class StorageTests(unittest.TestCase):
    def test_alias_and_history_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            store = DeviceStore(path)
            store.set_alias("AA-BB-CC-DD-EE-FF", "Desk Pi")
            device = Neighbor(IPv4Address("192.168.1.10"), mac="AA:BB:CC:DD:EE:FF", hostname="pi.local")
            aliased = store.apply_aliases([device])
            self.assertEqual(aliased[0].alias, "Desk Pi")
            store.record(aliased, datetime(2026, 10, 24, tzinfo=timezone.utc))

            reloaded = DeviceStore(path)
            history = reloaded.history("Desk Pi")
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["ips"], ["192.168.1.10"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_remove_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceStore(Path(directory) / "state.json")
            store.set_alias("192.168.1.20", "TV")
            store.record(store.apply_aliases([Neighbor(IPv4Address("192.168.1.20"))]))
            self.assertTrue(store.remove_alias("192.168.1.20"))
            self.assertFalse(store.remove_alias("192.168.1.20"))
            self.assertIsNone(store.history("192.168.1.20")[0]["alias"])

    def test_ip_only_history_merges_when_mac_is_learned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceStore(Path(directory) / "state.json")
            ip = IPv4Address("192.168.1.30")
            store.record([Neighbor(ip, hostname="speaker.local")])
            store.record([Neighbor(ip, mac="AA:BB:CC:DD:EE:FF", hostname="speaker.local")])
            self.assertEqual(len(store.history()), 1)
            self.assertEqual(store.history()[0]["id"], "mac:aa:bb:cc:dd:ee:ff")


if __name__ == "__main__":
    unittest.main()
