# CPU BRIDGE CONNECTION FIX
# Run this on your PC to check bridge status

Write-Host "Checking CPU Bridge Status..." -ForegroundColor Cyan

# Check if bridge is running
$bridge = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {$_.CommandLine -like "*claude_code_cpu_bridge*"}

if ($bridge) {
    Write-Host "✅ Bridge process found" -ForegroundColor Green
    Write-Host "PID: $($bridge.Id)" -ForegroundColor White
} else {
    Write-Host "❌ Bridge not running" -ForegroundColor Red
    Write-Host "Start it with: python claude_code_cpu_bridge.py" -ForegroundColor Yellow
}

# Check ports
Write-Host "`nChecking ports..." -ForegroundColor Cyan
$ports = @(8767, 8768)
foreach ($port in $ports) {
    $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($listener) {
        Write-Host "✅ Port $port is listening" -ForegroundColor Green
    } else {
        Write-Host "❌ Port $port not listening" -ForegroundColor Red
    }
}

# Test localhost connection
Write-Host "`nTesting connections..." -ForegroundColor Cyan
foreach ($port in $ports) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$port/health" -TimeoutSec 2 -ErrorAction Stop
        Write-Host "✅ localhost:$port responds: $($response.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "❌ localhost:$port not responding" -ForegroundColor Red
    }
}

# Get local IP
Write-Host "`nLocal IP addresses:" -ForegroundColor Cyan
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"} | ForEach-Object {
    Write-Host "  $($_.IPAddress)" -ForegroundColor White
}

Write-Host "`nBridge URL for Claude Code:" -ForegroundColor Yellow
Write-Host "  If on same machine: http://localhost:8767" -ForegroundColor White
Write-Host "  If remote access needed: http://<YOUR_IP>:8767" -ForegroundColor White
