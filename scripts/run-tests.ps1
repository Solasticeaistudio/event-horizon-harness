$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $Root "attestation")
npm test
Set-Location $Root
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
