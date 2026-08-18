from __future__ import annotations

import unittest

from rangeatlas.correlation import merge_assets
from rangeatlas.models import Asset, Service


class CorrelationTests(unittest.TestCase):
    def test_assets_merge_without_duplicate_services(self) -> None:
        nmap = Asset(
            address="10.77.0.20",
            hostname="range-web.test",
            services=[Service(port=8080, protocol="tcp", name="http", source="Nmap")],
            sources=["Nmap"],
        )
        metasploit = Asset(
            address="10.77.0.20",
            os_name="Linux",
            services=[Service(port=8080, protocol="tcp", name="http", product="RangeWeb", source="Metasploit")],
            sources=["Metasploit"],
        )
        merged = merge_assets([[nmap], [metasploit]])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].services), 1)
        self.assertEqual(merged[0].services[0].product, "RangeWeb")
        self.assertEqual(merged[0].sources, ["Metasploit", "Nmap"])


if __name__ == "__main__":
    unittest.main()

