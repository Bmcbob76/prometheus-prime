# ========================================
# FIX AND PULL - One Command Solution
# ========================================
# Automatically handles changes and pulls latest code
# ========================================

Write-Host ""
Write-Host "🔄 FIX AND PULL - Automatic Solution" -ForegroundColor Cyan
Write-Host ""

$BRANCH = "claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG"

# Navigate to repository root if needed
if (Test-Path "tools\anti-detect-browser") {
    Write-Host "Moving to repository root..." -ForegroundColor Yellow
    Set-Location ..\..\
}

# Check current directory
$currentDir = (Get-Location).Path
Write-Host "Working directory: $currentDir" -ForegroundColor Cyan
Write-Host ""

# Automatically stash changes
Write-Host "[1/2] Stashing any local changes..." -ForegroundColor Cyan
git stash push -u -m "Auto-stash for safe pull - $(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Changes stashed" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Nothing to stash (or already clean)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[2/2] Pulling latest code..." -ForegroundColor Cyan
git pull origin $BRANCH

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ PULL SUCCESSFUL!" -ForegroundColor Green -BackgroundColor Black
    Write-Host ""
    Write-Host "Latest code downloaded successfully!" -ForegroundColor Green
    Write-Host ""

    # Show what's new
    Write-Host "New files available:" -ForegroundColor Cyan
    Write-Host "  ✅ INTEGRATE_GIT_TO_PC.bat" -ForegroundColor Green
    Write-Host "  ✅ INSTALL_OMEGA_BROWSER.bat" -ForegroundColor Green
    Write-Host "  ✅ VERIFY_PC_INTEGRATION.ps1" -ForegroundColor Green
    Write-Host "  ✅ VERIFY_OMEGA_BROWSER.ps1" -ForegroundColor Green
    Write-Host "  ✅ And more..." -ForegroundColor Green
    Write-Host ""

    # Check stash
    $stashList = git stash list
    if ($stashList) {
        Write-Host "📦 Your changes are safely stashed" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To restore them later:" -ForegroundColor Cyan
        Write-Host "  git stash pop" -ForegroundColor White
        Write-Host ""
    }

    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. INTEGRATE_GIT_TO_PC.bat       (Get all 27,485+ files)" -ForegroundColor White
    Write-Host "  2. INSTALL_OMEGA_BROWSER.bat     (Install browser)" -ForegroundColor White
    Write-Host "  3. LAUNCH_OMEGA_BROWSER.bat      (Test browser)" -ForegroundColor White
    Write-Host ""

} else {
    Write-Host ""
    Write-Host "❌ PULL FAILED!" -ForegroundColor Red -BackgroundColor Black
    Write-Host ""
    Write-Host "Error during pull. Please check the error message above." -ForegroundColor Red
    Write-Host ""
    Write-Host "Try:" -ForegroundColor Yellow
    Write-Host "  git status" -ForegroundColor White
    Write-Host ""
}
