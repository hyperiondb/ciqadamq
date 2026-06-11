$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

docker compose up -d --build
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

$deadline = (Get-Date).AddMinutes(3)
while ($true) {
    $unhealthy = docker compose ps --format json | ConvertFrom-Json | Where-Object { $_.Service -ne "postgres" -and $_.Health -ne "healthy" }
    if (-not $unhealthy) { break }
    if ((Get-Date) -gt $deadline) {
        docker compose ps
        docker compose logs --tail 50
        throw "cluster did not become healthy within 3 minutes"
    }
    Start-Sleep -Seconds 2
}

Write-Host "cluster healthy, running tests"
cargo test --test cluster_e2e -- --ignored --nocapture
$result = $LASTEXITCODE

if ($env:KEEP_CLUSTER -ne "1") {
    docker compose down
}

exit $result
