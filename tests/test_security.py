from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rangeatlas.security import EvidenceError, ScopePolicy, clean_evidence_text, parse_xml_bounded, redact_text


ROOT = Path(__file__).resolve().parents[1]


class ScopePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = ScopePolicy.from_toml(ROOT / "config" / "scope.toml")

    def test_allows_declared_private_address(self) -> None:
        self.assertTrue(self.policy.evaluate("10.77.0.20").allowed)

    def test_denies_public_address(self) -> None:
        decision = self.policy.evaluate("8.8.8.8")
        self.assertFalse(decision.allowed)
        self.assertIn("public", decision.reason)

    def test_denies_private_address_outside_declared_range(self) -> None:
        decision = self.policy.evaluate("10.78.0.20")
        self.assertFalse(decision.allowed)
        self.assertIn("outside", decision.reason)

    def test_denies_hostname_without_dns_resolution(self) -> None:
        decision = self.policy.evaluate("range-web.test")
        self.assertFalse(decision.allowed)
        self.assertIn("literal IP", decision.reason)

    def test_require_reports_every_denial(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "8.8.8.8"):
            self.policy.require(["10.77.0.20", "8.8.8.8"])


class EvidenceSafetyTests(unittest.TestCase):
    def test_redacts_common_secret_shapes(self) -> None:
        value = "Authorization: Bearer abc123 password=hunter2 reed@example.test"
        result = redact_text(value)
        self.assertNotIn("abc123", result)
        self.assertNotIn("hunter2", result)
        self.assertNotIn("reed@example.test", result)

    def test_html_is_reduced_to_plain_text(self) -> None:
        self.assertEqual(clean_evidence_text("<p>Safe <b>detail</b></p>"), "Safe detail")

    def test_xml_entity_declarations_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "entity.xml"
            candidate.write_text(
                '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(EvidenceError, "entity declaration"):
                parse_xml_bounded(candidate)


if __name__ == "__main__":
    unittest.main()

