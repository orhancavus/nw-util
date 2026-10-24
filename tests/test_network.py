import unittest
from ipaddress import IPv4Address, IPv4Network
from unittest.mock import patch

from nw_util.models import NetworkContext
from nw_util.network import _linux_context, _normalize_mac, _parse_oui_lines, _ping, read_neighbors, scan


class NetworkTests(unittest.TestCase):
    def test_normalize_mac(self) -> None:
        self.assertEqual(_normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(_normalize_mac("00:00:00:00:00:00"))

    @patch("nw_util.network._read_oui_database", return_value={})
    @patch("nw_util.network.read_neighbors", return_value={})
    @patch("nw_util.network.ping_sweep", return_value={})
    def test_override_does_not_add_self_outside_network(self, *_mocks: object) -> None:
        context = NetworkContext(IPv4Address("192.168.1.20"), IPv4Network("10.0.0.0/30"))
        self.assertEqual(scan(context), [])

    def test_nmap_oui_format(self) -> None:
        result = _parse_oui_lines(["F0C850 Huawei Technologies", "# comment"])
        self.assertEqual(result, {"F0C850": "Huawei Technologies"})

    @patch("nw_util.network._run")
    def test_linux_context_from_iproute_json(self, run: object) -> None:
        run.side_effect = [
            '[{"dst":"default","gateway":"192.168.1.1","dev":"eth0"}]',
            '[{"addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24}]}]',
        ]
        context = _linux_context()
        self.assertIsNotNone(context)
        self.assertEqual(str(context.network), "192.168.1.0/24")
        self.assertEqual(context.interface, "eth0")

    @patch("nw_util.network.subprocess.run")
    def test_ping_returns_latency(self, run: object) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = "64 bytes from 192.168.1.1: time=3.42 ms"
        self.assertEqual(_ping(IPv4Address("192.168.1.1"), 0.5), 3.42)

    @patch("nw_util.network._run")
    def test_linux_neighbor_state(self, run: object) -> None:
        run.side_effect = [
            "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE\n",
            "",
            "",
        ]
        neighbor = read_neighbors()[IPv4Address("192.168.1.5")]
        self.assertEqual(neighbor, ("AA:BB:CC:DD:EE:FF", None, "stale"))


if __name__ == "__main__":
    unittest.main()

