import unittest
from ipaddress import IPv4Address

from nw_util.cli import build_parser, diff_devices
from nw_util.models import Neighbor
from nw_util.render import render_csv


class CliTests(unittest.TestCase):
    def test_existing_flat_scan_options_remain_supported(self) -> None:
        args = build_parser().parse_args(["--deep", "--format", "csv"])
        self.assertTrue(args.deep)
        self.assertEqual(args.format, "csv")
        self.assertIsNone(args.command)

    def test_watch_detects_responsive_transition(self) -> None:
        before = Neighbor(IPv4Address("192.168.1.20"), mac="AA:BB:CC:DD:EE:FF", responsive=False)
        after = Neighbor(IPv4Address("192.168.1.20"), mac="AA:BB:CC:DD:EE:FF", responsive=True)
        events = diff_devices({"device": before}, {"device": after})
        self.assertEqual(events, [("ONLINE", after)])

    def test_csv_output(self) -> None:
        output = render_csv([Neighbor(IPv4Address("192.168.1.5"), hostname="pi.local")])
        self.assertIn("type,name,status,ip", output)
        self.assertIn("192.168.1.5", output)


if __name__ == "__main__":
    unittest.main()
