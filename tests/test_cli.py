from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path

from rangeatlas.cli import main


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_scope_command_returns_nonzero_when_any_target_is_denied(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                [
                    "scope",
                    "--policy",
                    str(ROOT / "config" / "scope.toml"),
                    "10.77.0.20",
                    "8.8.8.8",
                ]
            )
        self.assertEqual(result, 2)
        self.assertIn("ALLOW", output.getvalue())
        self.assertIn("DENY", output.getvalue())


if __name__ == "__main__":
    unittest.main()

