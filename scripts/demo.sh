#!/usr/bin/env sh
set -eu

python -m rangeatlas build --manifest examples/demo/manifest.toml --out build/demo
printf '%s\n' "Open build/demo/report.html"

