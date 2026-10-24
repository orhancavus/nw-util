import unittest
from ipaddress import IPv4Address

from nw_util.classify import present
from nw_util.models import Neighbor


class ClassificationTests(unittest.TestCase):
    def test_gateway_is_router(self) -> None:
        item = present(Neighbor(IPv4Address("192.168.1.1"), is_gateway=True))
        self.assertEqual((item.emoji, item.device_type, item.status), ("🌐", "Router", "Online"))

    def test_hostname_classifies_phone(self) -> None:
        item = present(Neighbor(IPv4Address("192.168.1.20"), hostname="alex-iphone"))
        self.assertEqual(item.device_type, "Mobile")
        self.assertEqual(item.name, "alex-iphone")

    def test_self_status_wins(self) -> None:
        item = present(Neighbor(IPv4Address("192.168.1.50"), hostname="workstation", is_self=True))
        self.assertEqual(item.status, "This device")
        self.assertEqual(item.device_type, "Computer")

    def test_services_classify_printer(self) -> None:
        item = present(Neighbor(IPv4Address("192.168.1.60"), services=("631/ipp (CUPS)",)))
        self.assertEqual(item.device_type, "Printer")

    def test_vendor_classifies_television(self) -> None:
        item = present(Neighbor(IPv4Address("192.168.1.22"), vendor="Shenzhen Skyworth Digital Technology"))
        self.assertEqual(item.device_type, "Television")

    def test_mdns_service_classifies_airplay(self) -> None:
        item = present(Neighbor(IPv4Address("192.168.1.43"), services=("airplay:7000",)))
        self.assertEqual(item.device_type, "Television")

    def test_hostname_with_suffix_classifies_ipad(self) -> None:
        item = present(Neighbor(IPv4Address("192.168.1.42"), hostname="Orhan-iPadi.local"))
        self.assertEqual(item.device_type, "Mobile")


if __name__ == "__main__":
    unittest.main()

