# PROMETHEUS PRIME - ARSENAL INSTALLATION SCRIPT
# Authority Level 11.0 - Commander Bobby Don McWilliams II

Write-Host "🔥 PROMETHEUS PRIME ARSENAL INSTALLER 🔥" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$toolsDir = "C:\SecurityTools"
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

# HASHCAT
Write-Host "[1/5] Installing Hashcat..." -ForegroundColor Yellow
$hashcatUrl = "https://hashcat.net/files/hashcat-6.2.6.7z"
$hashcatZip = "$toolsDir\hashcat.7z"
if (-not (Test-Path "$toolsDir\hashcat-6.2.6")) {
    Invoke-WebRequest -Uri $hashcatUrl -OutFile $hashcatZip
    Write-Host "  ✅ Downloaded. Extract manually with 7-Zip to $toolsDir" -ForegroundColor Green
}

# JOHN THE RIPPER
Write-Host "[2/5] Installing John the Ripper..." -ForegroundColor Yellow
$johnUrl = "https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.7z"
$johnZip = "$toolsDir\john.7z"
if (-not (Test-Path "$toolsDir\john-1.9.0-jumbo-1")) {
    Invoke-WebRequest -Uri $johnUrl -OutFile $johnZip
    Write-Host "  ✅ Downloaded. Extract manually with 7-Zip to $toolsDir" -ForegroundColor Green
}

# HYDRA (Windows build)
Write-Host "[3/5] Installing THC-Hydra..." -ForegroundColor Yellow
$hydraUrl = "https://github.com/maaaaz/thc-hydra-windows/archive/refs/heads/master.zip"
$hydraZip = "$toolsDir\hydra.zip"
if (-not (Test-Path "$toolsDir\thc-hydra-windows-master")) {
    Invoke-WebRequest -Uri $hydraUrl -OutFile $hydraZip
    Expand-Archive -Path $hydraZip -DestinationPath $toolsDir -Force
    Write-Host "  ✅ Installed to $toolsDir\thc-hydra-windows-master" -ForegroundColor Green
}

# MASSCAN
Write-Host "[4/5] Installing Masscan..." -ForegroundColor Yellow
$masscanUrl = "https://github.com/robertdavidgraham/masscan/releases/download/1.3.2/masscan-1.3.2-win64.zip"
$masscanZip = "$toolsDir\masscan.zip"
if (-not (Test-Path "$toolsDir\masscan")) {
    Invoke-WebRequest -Uri $masscanUrl -OutFile $masscanZip
    Expand-Archive -Path $masscanZip -DestinationPath "$toolsDir\masscan" -Force
    Write-Host "  ✅ Installed to $toolsDir\masscan" -ForegroundColor Green
}

# NMAP (verify)
Write-Host "[5/5] Verifying Nmap..." -ForegroundColor Yellow
if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Host "  ✅ Nmap already installed" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Nmap not found. Download from: https://nmap.org/download.html" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "🎯 ARSENAL DOWNLOAD COMPLETE" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "MANUAL STEPS REQUIRED:" -ForegroundColor Yellow
Write-Host "1. Extract hashcat.7z with 7-Zip" -ForegroundColor White
Write-Host "2. Extract john.7z with 7-Zip" -ForegroundColor White
Write-Host "3. Install metasploitframework-latest.msi (downloading separately)" -ForegroundColor White
Write-Host "`nAll tools location: $toolsDir" -ForegroundColor Green
Write-Host "`nAdd to PATH:" -ForegroundColor Yellow
Write-Host "`$env:Path += ';$toolsDir\hashcat-6.2.6;$toolsDir\john-1.9.0-jumbo-1\run;$toolsDir\masscan;$toolsDir\thc-hydra-windows-master'" -ForegroundColor White
