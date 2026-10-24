import tempfile
import time
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from nw_util.api import create_app
from nw_util.models import Neighbor, NetworkContext
from nw_util.services.scanner import ScanResult
from nw_util.storage import DeviceStore


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = DeviceStore(Path(self.temporary.name) / "state.json")
        self.app = create_app(store=self.store)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.client.close()
        self.app.state.jobs.shutdown()
        self.temporary.cleanup()

    def test_health_capabilities_alias_and_history(self) -> None:
        self.assertEqual(self.client.get("/api/v1/health").status_code, 200)
        self.assertEqual(self.client.head("/").status_code, 200)
        capabilities = self.client.get("/api/v1/capabilities").json()
        self.assertTrue(capabilities["local_only"])

        saved = self.client.put("/api/v1/aliases/192.168.1.8", json={"name": "Desk Pi"})
        self.assertEqual(saved.status_code, 200)
        device = Neighbor(IPv4Address("192.168.1.8"), hostname="pi")
        self.store.record(self.store.apply_aliases([device]))
        history = self.client.get("/api/v1/history?q=Desk%20Pi").json()
        self.assertEqual(history["count"], 1)

    def test_scan_job_returns_structured_devices(self) -> None:
        context = NetworkContext(IPv4Address("192.168.1.2"), IPv4Network("192.168.1.0/24"), "en0")
        result = ScanResult(context, (Neighbor(IPv4Address("192.168.1.2"), hostname="laptop"),))

        def fake_collect(_options, _store, *, progress=None):
            if progress:
                progress("probing_hosts")
                progress("complete")
            return result

        with patch("nw_util.api.jobs.collect_devices", side_effect=fake_collect):
            created = self.client.post("/api/v1/scans", json={}).json()
            for _ in range(50):
                job = self.client.get(f"/api/v1/scans/{created['id']}").json()
                if job["status"] == "completed":
                    break
                time.sleep(0.01)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["result"]["devices"][0]["ip"], "192.168.1.2")
        exported = self.client.get(f"/api/v1/scans/{created['id']}/export?format=csv")
        self.assertEqual(exported.status_code, 200)
        self.assertIn("192.168.1.2", exported.text)

    def test_invalid_scan_is_rejected(self) -> None:
        response = self.client.post("/api/v1/scans", json={"workers": 0})
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
