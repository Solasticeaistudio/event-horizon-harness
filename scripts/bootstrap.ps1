$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
python -m pip install -e .
Set-Location (Join-Path $Root "hardproof")
npm install
npm run build
Set-Location $Root
