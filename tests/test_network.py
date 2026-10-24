import unittest
from ipaddress import IPv4Address, IPv4Network
from unittest.mock import patch

from nw_util.models import NetworkContext
from nw_util.network import _normalize_mac, scan


class NetworkTests(unittest.TestCase):
    def test_normalize_mac(self) -> None:
        self.assertEqual(_normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(_normalize_mac("00:00:00:00:00:00"))

    @patch("nw_util.network._read_oui_database", return_value={})
    @patch("nw_util.network.read_neighbors", return_value={})
    @patch("nw_util.network.ping_sweep", return_value=set())
    def test_override_does_not_add_self_outside_network(self, *_mocks: object) -> None:
        context = NetworkContext(IPv4Address("192.168.1.20"), IPv4Network("10.0.0.0/30"))
        self.assertEqual(scan(context), [])


if __name__ == "__main__":
    unittest.main()

