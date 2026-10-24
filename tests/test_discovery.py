import unittest
from ipaddress import IPv4Address, IPv4Network

from nw_util.discovery import MdnsRecord, merge_mdns, record_from_service
from nw_util.models import Neighbor, NetworkContext


class FakeInfo:
    server = "Living-Room-TV.local."
    port = 7000
    decoded_properties = {"model": "Apple TV 4K", "manufacturer": "Apple"}

    def parsed_addresses(self) -> list[str]:
        return ["192.168.1.22", "fe80::1%en0"]


class DiscoveryTests(unittest.TestCase):
    def test_service_record_extracts_metadata(self) -> None:
        records = record_from_service("_airplay._tcp.local.", "Living Room._airplay._tcp.local.", FakeInfo())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].model, "Apple TV 4K")
        self.assertEqual(records[0].services, ("airplay:7000",))

    def test_mdns_adds_and_merges_devices(self) -> None:
        context = NetworkContext(IPv4Address("192.168.1.10"), IPv4Network("192.168.1.0/24"))
        devices = [Neighbor(IPv4Address("192.168.1.22"), mac="00:11:22:33:44:55")]
        records = {
            IPv4Address("192.168.1.22"): MdnsRecord(
                IPv4Address("192.168.1.22"), hostname="tv.local", model="TV", services=("airplay:7000",)
            ),
            IPv4Address("192.168.1.30"): MdnsRecord(
                IPv4Address("192.168.1.30"), hostname="printer.local", services=("ipp:631",)
            ),
        }
        merged = merge_mdns(devices, records, context)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0].hostname, "tv.local")
        self.assertEqual(merged[1].services, ("ipp:631",))


if __name__ == "__main__":
    unittest.main()
