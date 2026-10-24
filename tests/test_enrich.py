import unittest
from ipaddress import IPv4Address

from nw_util.enrich import parse_nmap_services


class EnrichmentTests(unittest.TestCase):
    def test_parse_nmap_services(self) -> None:
        xml = """<?xml version='1.0'?>
        <nmaprun><host><address addr='192.168.1.20' addrtype='ipv4'/><ports>
          <port protocol='tcp' portid='631'><state state='open'/><service name='ipp' product='CUPS'/></port>
          <port protocol='tcp' portid='22'><state state='closed'/><service name='ssh'/></port>
        </ports></host></nmaprun>"""
        result = parse_nmap_services(xml)
        self.assertEqual(result[IPv4Address("192.168.1.20")], ("631/ipp (CUPS)",))

    def test_invalid_xml_is_ignored(self) -> None:
        self.assertEqual(parse_nmap_services("not xml"), {})


if __name__ == "__main__":
    unittest.main()
