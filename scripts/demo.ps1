$ErrorActionPreference = "Stop"
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepositoryRoot
try {
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "TypeScript build failed" }
    python -m event_horizon.public_demo
    if ($LASTEXITCODE -ne 0) { throw "public demo failed" }
}
finally {
    Pop-Location
}
