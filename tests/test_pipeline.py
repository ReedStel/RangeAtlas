from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rangeatlas.cli import build_from_manifest


ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def test_demo_builds_three_safe_deterministic_reports(self) -> None:
        manifest = ROOT / "examples" / "demo" / "manifest.toml"
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self.assertEqual(build_from_manifest(manifest, Path(first)), 0)
            self.assertEqual(build_from_manifest(manifest, Path(second)), 0)

            expected = {"report.html", "report.json", "report.md"}
            self.assertEqual({path.name for path in Path(first).iterdir()}, expected)
            for name in expected:
                self.assertEqual((Path(first) / name).read_bytes(), (Path(second) / name).read_bytes())

            report = json.loads((Path(first) / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(len(report["assets"]), 2)
            self.assertEqual(len(report["findings"]), 3)
            self.assertEqual(report["traffic"]["packets"], 8)

            all_output = "".join(
                (Path(first) / name).read_text(encoding="utf-8") for name in sorted(expected)
            )
            self.assertNotIn("fixture-token-never-imported", all_output)
            self.assertNotIn("THIS_VALUE_MUST_NEVER_BE_IMPORTED", all_output)
            self.assertIn("RangeAtlas Synthetic Validation", all_output)


if __name__ == "__main__":
    unittest.main()

