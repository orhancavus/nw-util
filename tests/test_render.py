import json
import unittest
from ipaddress import IPv4Address, IPv4Network

from nw_util.models import Neighbor, NetworkContext
from nw_util.render import render_json, render_table


class RenderTests(unittest.TestCase):
    def test_json_output(self) -> None:
        output = json.loads(render_json([Neighbor(IPv4Address("10.0.0.1"), is_gateway=True)]))
        self.assertEqual(output[0]["type"], "Router")
        self.assertEqual(output[0]["ip"], "10.0.0.1")

    def test_plain_table_has_no_ansi_codes(self) -> None:
        context = NetworkContext(IPv4Address("10.0.0.2"), IPv4Network("10.0.0.0/24"))
        output = render_table([Neighbor(IPv4Address("10.0.0.1"), is_gateway=True)], context, color=False)
        self.assertIn("🌐  Router", output)
        self.assertNotIn("\033[", output)

    def test_empty_table(self) -> None:
        context = NetworkContext(IPv4Address("192.168.1.2"), IPv4Network("10.0.0.0/30"))
        output = render_table([], context, color=False)
        self.assertIn("0 devices found", output)



if __name__ == "__main__":
    unittest.main()

