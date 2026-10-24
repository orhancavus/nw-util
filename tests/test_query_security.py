import unittest
from ipaddress import IPv4Address

from nw_util.models import Neighbor
from nw_util.query import filter_devices, sort_devices
from nw_util.security import findings_for, resolve_target


class QuerySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.devices = [
            Neighbor(IPv4Address("192.168.1.10"), alias="Desk Pi", vendor="Raspberry Pi", latency_ms=2.5),
            Neighbor(IPv4Address("192.168.1.20"), hostname="printer.local", services=("631/ipp",), latency_ms=8.0),
        ]

    def test_filter_and_sort(self) -> None:
        self.assertEqual(filter_devices(self.devices, device_type="printer")[0].ip, IPv4Address("192.168.1.20"))
        self.assertEqual(sort_devices(self.devices, "latency")[0].ip, IPv4Address("192.168.1.10"))

    def test_security_findings(self) -> None:
        findings = findings_for(("23/telnet", "80/http"))
        self.assertEqual(findings[0].severity, "high")
        self.assertTrue(any("HTTPS" in finding.message for finding in findings))

    def test_resolve_alias(self) -> None:
        self.assertEqual(resolve_target("Desk Pi", self.devices), IPv4Address("192.168.1.10"))


if __name__ == "__main__":
    unittest.main()
