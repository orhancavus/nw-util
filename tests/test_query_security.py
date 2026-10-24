import unittest
from ipaddress import IPv4Address
from unittest.mock import patch

from nw_util.models import Neighbor
from nw_util.query import filter_devices, sort_devices
from nw_util.security import findings_for, inspect_ip, parse_security_xml, resolve_target


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

    def test_parse_security_profile_with_service_and_os(self) -> None:
        xml = """<?xml version='1.0'?>
        <nmaprun><host><address addr='192.168.1.10' addrtype='ipv4'/><ports>
          <port protocol='tcp' portid='22'><state state='open'/>
            <service name='ssh' product='OpenSSH' version='9.2' ostype='Linux' conf='10'>
              <cpe>cpe:/a:openbsd:openssh:9.2</cpe><cpe>cpe:/o:linux:linux_kernel</cpe>
            </service>
          </port>
        </ports><os><osmatch name='Linux 5.X' accuracy='96'>
          <osclass type='general purpose' vendor='Linux' osfamily='Linux' osgen='5.X'>
            <cpe>cpe:/o:linux:linux_kernel:5</cpe>
          </osclass>
        </osmatch></os></host></nmaprun>"""
        services, guesses = parse_security_xml(xml, IPv4Address("192.168.1.10"))
        self.assertEqual(services[0].product, "OpenSSH")
        self.assertEqual(services[0].confidence, 10)
        self.assertEqual(guesses[0].name, "Linux 5.X")
        self.assertEqual(guesses[0].accuracy, 96)
        self.assertEqual(guesses[0].source, "Nmap TCP/IP fingerprint")

    @patch("nw_util.security._nmap_profile", return_value=((), (), "OS fingerprinting requires root."))
    @patch("nw_util.security.shutil.which", return_value="/usr/bin/nmap")
    def test_os_detection_limitation_is_reported(self, *_mocks: object) -> None:
        profile = inspect_ip(IPv4Address("192.168.1.10"), os_detect=True)
        self.assertIn("requires root", profile.os_detection_note)


if __name__ == "__main__":
    unittest.main()
