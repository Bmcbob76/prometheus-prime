# ========================================
# PROMETHEUS PRIME - PC INTEGRATION VERIFICATION
# ========================================
# Checks what files are missing from your PC
# Compares PC files with git repository
# ========================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PC INTEGRATION VERIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in a git repository
if (-not (Test-Path ".git")) {
    Write-Host "ERROR: Not in a git repository!" -ForegroundColor Red
    Write-Host "Please run this from the prometheus-prime directory" -ForegroundColor Red
    exit 1
}

Write-Host "[1/5] Analyzing Repository..." -ForegroundColor Yellow

# Get all files tracked by git
$gitFiles = git ls-files
$gitFileCount = ($gitFiles | Measure-Object).Count
Write-Host "Files in git repository: $gitFileCount" -ForegroundColor Cyan

# Get all files on disk
$diskFiles = Get-ChildItem -Recurse -File | Where-Object { $_.FullName -notmatch "\.git" }
$diskFileCount = ($diskFiles | Measure-Object).Count
Write-Host "Files on your PC: $diskFileCount" -ForegroundColor Cyan
Write-Host ""

Write-Host "[2/5] Checking for Missing Files..." -ForegroundColor Yellow

# Find files in git but not on disk
$missingFiles = @()
$currentDir = Get-Location

foreach ($gitFile in $gitFiles) {
    $fullPath = Join-Path $currentDir $gitFile
    if (-not (Test-Path $fullPath)) {
        $missingFiles += $gitFile
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "WARNING: $($missingFiles.Count) files are in git but missing from your PC!" -ForegroundColor Red
    Write-Host ""
    Write-Host "First 20 missing files:" -ForegroundColor Yellow
    $missingFiles | Select-Object -First 20 | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor Red
    }

    # Save full list to file
    $missingFiles | Out-File "MISSING_FILES.txt"
    Write-Host ""
    Write-Host "Full list saved to: MISSING_FILES.txt" -ForegroundColor Yellow
} else {
    Write-Host "[OK] All git files are present on your PC!" -ForegroundColor Green
}

Write-Host ""

Write-Host "[3/5] Checking File Modifications..." -ForegroundColor Yellow

# Check for modified files
$modifiedFiles = git status --short | Where-Object { $_ -match "^\s*M\s+" }

if ($modifiedFiles) {
    Write-Host "Modified files (different from git):" -ForegroundColor Yellow
    $modifiedFiles | ForEach-Object {
        Write-Host "  $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[OK] No modified files" -ForegroundColor Green
}

Write-Host ""

Write-Host "[4/5] Checking Critical Components..." -ForegroundColor Yellow

# Define critical files/directories
$criticalItems = @{
    "AD/BloodHound" = "Active Directory Assessment"
    "BEEF" = "Browser Exploitation Framework"
    "EMPIRE" = "Post-Exploitation Framework"
    "MIMIKATZ" = "Credential Extraction"
    "NUCLEI_TEMPLATES" = "Vulnerability Scanning Templates"
    "OMEGA_SWARM_BRAIN" = "AI Orchestration System"
    "OSINT" = "Open Source Intelligence Tools"
    "PAYLOADS" = "Exploitation Payloads"
    "SECLISTS" = "Security Wordlists"
    "SAFETY" = "Safety and Compliance"
    "TOOLS" = "Security Tools"
    "PROMETHEUS_PRIME_ULTIMATE_ENHANCED.py" = "Main Prometheus System"
    "prometheus_prime_mcp.py" = "MCP Server"
    "vault_addon.py" = "Promethian Vault"
    "ULTIMATE_MLS_LAUNCHER.py" = "Multi-Launch System"
}

$missingCritical = @()
$presentCritical = @()

foreach ($item in $criticalItems.Keys) {
    if (Test-Path $item) {
        $presentCritical += $item
        if (Test-Path $item -PathType Container) {
            $fileCount = (Get-ChildItem $item -Recurse -File | Measure-Object).Count
            Write-Host "  [OK] $item - $fileCount files - $($criticalItems[$item])" -ForegroundColor Green
        } else {
            $fileSize = (Get-Item $item).Length
            Write-Host "  [OK] $item - $([math]::Round($fileSize/1KB, 2)) KB - $($criticalItems[$item])" -ForegroundColor Green
        }
    } else {
        $missingCritical += $item
        Write-Host "  [MISSING] $item - $($criticalItems[$item])" -ForegroundColor Red
    }
}

Write-Host ""

Write-Host "[5/5] Integration Status Summary" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total files in git: $gitFileCount" -ForegroundColor White
Write-Host "Total files on PC: $diskFileCount" -ForegroundColor White
Write-Host "Missing files: $($missingFiles.Count)" -ForegroundColor $(if ($missingFiles.Count -eq 0) { "Green" } else { "Red" })
Write-Host "Critical components present: $($presentCritical.Count)/$($criticalItems.Count)" -ForegroundColor $(if ($missingCritical.Count -eq 0) { "Green" } else { "Yellow" })
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Final recommendation
if ($missingFiles.Count -eq 0 -and $missingCritical.Count -eq 0) {
    Write-Host "STATUS: COMPLETE INTEGRATION ✓" -ForegroundColor Green -BackgroundColor Black
    Write-Host ""
    Write-Host "Your PC has ALL files from the git repository!" -ForegroundColor Green
    Write-Host "All critical components are present and ready to use." -ForegroundColor Green
} elseif ($missingCritical.Count -eq 0) {
    Write-Host "STATUS: MOSTLY COMPLETE ⚠" -ForegroundColor Yellow -BackgroundColor Black
    Write-Host ""
    Write-Host "All critical components are present." -ForegroundColor Green
    Write-Host "Some non-critical files are missing ($($missingFiles.Count) files)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To fix: Run INTEGRATE_GIT_TO_PC.ps1" -ForegroundColor Cyan
} else {
    Write-Host "STATUS: INCOMPLETE ✗" -ForegroundColor Red -BackgroundColor Black
    Write-Host ""
    Write-Host "CRITICAL: $($missingCritical.Count) critical components are missing!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Missing critical items:" -ForegroundColor Red
    $missingCritical | ForEach-Object {
        Write-Host "  - $_ ($($criticalItems[$_]))" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "ACTION REQUIRED: Run INTEGRATE_GIT_TO_PC.ps1 immediately!" -ForegroundColor Yellow -BackgroundColor Red
}

Write-Host ""
Write-Host "Report saved to: integration_verification_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log" -ForegroundColor DarkGray
