param(
    [int]$ProfileSecs = 120,
    [int]$Subs = 1000
)

$repo = $PWD.Path
$env:PROFILE_SECS = "$ProfileSecs"
Remove-Item "$repo\data\users-profiling.db" -ErrorAction SilentlyContinue

Start-Job -Name perfload -ArgumentList $repo, $Subs {
    param($repo, $subs)
    Set-Location $repo
    $env:PERF_NODES = '127.0.0.1:21883'
    $env:PERF_API   = 'http://127.0.0.1:28090'
    $env:PERF_SUBS  = "$subs"
    foreach ($i in 1..300) {
        $c = New-Object Net.Sockets.TcpClient
        try { $c.Connect('127.0.0.1', 28090); $c.Close(); break } catch { Start-Sleep -Seconds 2 }
    }
    Start-Sleep -Seconds 2
    cargo run --release --features perf --bin perf
} | Out-Null

Write-Host "Broker building/starting under flamegraph on isolated ports 21883/28090 (first run recompiles, ~6 min)."
Write-Host "Load fires automatically once :28090 is up; broker self-exits after $ProfileSecs s and writes flamegraph.svg."

cargo flamegraph --profile profiling --bin ciqadamq -- config-profiling.toml

Stop-Job -Name perfload -ErrorAction SilentlyContinue
Write-Host "`n--- perf output ---"
Receive-Job -Name perfload -ErrorAction SilentlyContinue
Remove-Job -Name perfload -Force -ErrorAction SilentlyContinue
Write-Host "`nDone -> flamegraph.svg"
