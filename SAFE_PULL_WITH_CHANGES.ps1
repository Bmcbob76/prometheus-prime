# ========================================
# SAFE GIT PULL - Handles Unstaged Changes
# ========================================
# Safely pulls latest code even with local changes
# ========================================

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "║              🔄 SAFE GIT PULL WITH CHANGES 🔄                ║" -ForegroundColor Cyan
Write-Host "║                                                               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$BRANCH = "claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG"

# Navigate to repository root
if (Test-Path "tools\anti-detect-browser") {
    Write-Host "[INFO] You're in a subdirectory. Moving to repository root..." -ForegroundColor Yellow
    Set-Location ..\..\
}

Write-Host "[1/6] Checking Current Status..." -ForegroundColor Cyan
Write-Host ""

# Check git status
$status = git status --short
if ($status) {
    Write-Host "You have unstaged changes:" -ForegroundColor Yellow
    Write-Host ""
    git status --short
    Write-Host ""
} else {
    Write-Host "No unstaged changes detected." -ForegroundColor Green
    Write-Host ""
}

Write-Host "[2/6] Showing What Changed..." -ForegroundColor Cyan
Write-Host ""

# Show what files are modified
$modifiedFiles = git status --short | Where-Object { $_ -match "^\s*M\s+" }
$untrackedFiles = git status --short | Where-Object { $_ -match "^\?\?\s+" }

if ($modifiedFiles) {
    Write-Host "Modified files:" -ForegroundColor Yellow
    $modifiedFiles | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host ""
}

if ($untrackedFiles) {
    Write-Host "Untracked files (new files):" -ForegroundColor Cyan
    $untrackedFiles | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
    Write-Host ""
}

Write-Host "[3/6] Stashing Your Changes..." -ForegroundColor Cyan

# Stash all changes including untracked files
$stashMessage = "Auto-stash before pull - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Creating stash: $stashMessage" -ForegroundColor Yellow

git stash push -u -m $stashMessage

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Changes safely stashed!" -ForegroundColor Green
    $stashed = $true
} else {
    Write-Host "⚠️  No changes to stash or stash failed" -ForegroundColor Yellow
    $stashed = $false
}

Write-Host ""
Write-Host "[4/6] Pulling Latest Code..." -ForegroundColor Cyan
Write-Host ""

# Pull latest changes
git pull origin $BRANCH

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Pull successful!" -ForegroundColor Green
    $pullSuccess = $true
} else {
    Write-Host ""
    Write-Host "❌ Pull failed!" -ForegroundColor Red
    $pullSuccess = $false
}

Write-Host ""
Write-Host "[5/6] Checking Stash..." -ForegroundColor Cyan

# List stashes
$stashList = git stash list
if ($stashList) {
    Write-Host ""
    Write-Host "Your stashed changes:" -ForegroundColor Yellow
    git stash list | Select-Object -First 5
    Write-Host ""
} else {
    Write-Host "No stashed changes." -ForegroundColor Green
}

Write-Host ""
Write-Host "[6/6] Restore Stashed Changes?" -ForegroundColor Cyan
Write-Host ""

if ($stashed -and $pullSuccess) {
    Write-Host "Would you like to restore your stashed changes now?" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  [Y] Yes - Restore my changes now" -ForegroundColor White
    Write-Host "  [N] No - Keep them stashed (I'll restore manually later)" -ForegroundColor White
    Write-Host "  [D] Delete - I don't need those changes" -ForegroundColor White
    Write-Host ""

    $choice = Read-Host "Your choice (Y/N/D)"

    switch ($choice.ToUpper()) {
        "Y" {
            Write-Host ""
            Write-Host "Restoring your stashed changes..." -ForegroundColor Cyan
            git stash pop

            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Changes restored successfully!" -ForegroundColor Green
            } else {
                Write-Host "⚠️  Conflicts detected! Please resolve manually." -ForegroundColor Yellow
                Write-Host "Run: git status" -ForegroundColor Cyan
            }
        }
        "N" {
            Write-Host ""
            Write-Host "✅ Changes kept in stash" -ForegroundColor Green
            Write-Host ""
            Write-Host "To restore later, run:" -ForegroundColor Cyan
            Write-Host "  git stash list        # See all stashes" -ForegroundColor White
            Write-Host "  git stash pop         # Restore latest stash" -ForegroundColor White
            Write-Host "  git stash apply       # Apply without removing from stash" -ForegroundColor White
        }
        "D" {
            Write-Host ""
            Write-Host "Deleting stashed changes..." -ForegroundColor Yellow
            git stash drop
            Write-Host "✅ Stash deleted" -ForegroundColor Green
        }
        default {
            Write-Host ""
            Write-Host "Invalid choice. Changes remain stashed." -ForegroundColor Yellow
            Write-Host "Run 'git stash pop' to restore them later." -ForegroundColor Cyan
        }
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                    ✅ PULL COMPLETE!                          " -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Show current status
Write-Host "Current Status:" -ForegroundColor Cyan
git status --short
if (-not (git status --short)) {
    Write-Host "  Working tree clean ✓" -ForegroundColor Green
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Run: .\INTEGRATE_GIT_TO_PC.bat" -ForegroundColor White
Write-Host "  2. Run: .\INSTALL_OMEGA_BROWSER.bat" -ForegroundColor White
Write-Host "  3. Run: .\LAUNCH_OMEGA_BROWSER.bat" -ForegroundColor White
Write-Host ""
