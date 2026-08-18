$ErrorActionPreference = 'Stop'

python -m rangeatlas build --manifest examples/demo/manifest.toml --out build/demo
Write-Host 'Open build/demo/report.html'
