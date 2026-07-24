$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $Root "hardproof")
npm test
Set-Location $Root
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
