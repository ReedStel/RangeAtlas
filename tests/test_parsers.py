from __future__ import annotations

import unittest
from pathlib import Path

from rangeatlas.parsers import parse_burp_xml, parse_metasploit_xml, parse_nmap_xml, parse_tshark_json


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


class ParserTests(unittest.TestCase):
    def test_nmap_assets_and_services(self) -> None:
        assets = parse_nmap_xml(FIXTURES / "nmap.xml")
        self.assertEqual([asset.address for asset in assets], ["10.77.0.10", "10.77.0.20"])
        self.assertEqual([service.port for service in assets[1].services], [22, 8080])
        self.assertEqual(assets[1].hostname, "range-web.test")

    def test_tshark_summary(self) -> None:
        summary = parse_tshark_json(FIXTURES / "tshark.json")
        self.assertEqual(summary.packets, 8)
        self.assertEqual(summary.protocols, {"DNS": 2, "HTTP": 4, "ICMP": 1, "TCP": 1})
        self.assertEqual(sum(item.packets for item in summary.conversations), 8)

    def test_burp_import_excludes_raw_messages(self) -> None:
        findings = parse_burp_xml(FIXTURES / "burp.xml")
        combined = repr(findings)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].target, "10.77.0.20")
        self.assertNotIn("fixture-token-never-imported", combined)
        self.assertNotIn("Authorization", combined)

    def test_metasploit_import_excludes_credentials_and_loot(self) -> None:
        assets, findings, validations = parse_metasploit_xml(FIXTURES / "metasploit.xml")
        combined = repr((assets, findings, validations))
        self.assertEqual(len(assets), 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(validations), 1)
        self.assertNotIn("THIS_VALUE_MUST_NEVER_BE_IMPORTED", combined)
        self.assertIn("excluded", validations[0].note)


if __name__ == "__main__":
    unittest.main()

