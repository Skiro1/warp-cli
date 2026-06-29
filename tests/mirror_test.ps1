# Test mirror failover by blocking first 3 mirrors via Windows Firewall
# Requires admin. Run: powershell -ExecutionPolicy Bypass .\tests\mirror_test.ps1
#
# If endpoints are still found after blocking 3 mirrors,
# it means fallback to ircfspace.github.io works.

$ErrorActionPreference = 'Stop'

function Add-OutboundBlockRule($name, $remoteAddr) {
    $existing = netsh advfirewall firewall show rule name=$name 2>$null
    if ($LASTEXITCODE -eq 0) { return }
    netsh advfirewall firewall add rule name=$name dir=out remoteip=$remoteAddr protocol=tcp action=block | Out-Null
    Write-Host "  Blocked $remoteAddr"
}

function Remove-BlockRule($name) {
    netsh advfirewall firewall delete rule name=$name 2>$null | Out-Null
}

Write-Host "=== Mirror Failover Test ==="
Write-Host "Blocking first 3 ip.json mirrors..."
Add-OutboundBlockRule "warp-test-gh" "github.com"
Add-OutboundBlockRule "warp-test-jsdelivr" "cdn.jsdelivr.net"
Add-OutboundBlockRule "warp-test-rawgh" "raw.githubusercontent.com"

Write-Host ""
Write-Host "Running scan with --community..."
$scan = & .\awarp.exe scan --community 2>&1 | Out-String
Write-Host $scan

Write-Host "=== Cleaning up test rules ==="
Remove-BlockRule "warp-test-gh"
Remove-BlockRule "warp-test-jsdelivr"
Remove-BlockRule "warp-test-rawgh"

if ($scan -match "got \d+ endpoints") {
    Write-Host "PASS: Fallback to ircfspace.github.io works!"
} else {
    Write-Host "FAIL: No endpoints found - all mirrors may be blocked"
}
