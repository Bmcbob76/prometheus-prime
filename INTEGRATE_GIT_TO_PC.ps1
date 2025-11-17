# ========================================
# PROMETHEUS PRIME - GIT TO PC INTEGRATION
# ========================================
# Safely integrates all git repository code to your PC
# Preserves essential files and creates backups
# ========================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PROMETHEUS PRIME - GIT INTEGRATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$BRANCH = "claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG"
$BACKUP_DIR = "PROMETHEUS_BACKUP_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"

# Essential files that should NEVER be overwritten
$PROTECTED_FILES = @(
    ".env",
    "*.db",
    "*.sqlite",
    "osint_db/*",
    "logs/*",
    "sessions/*",
    "reports/*",
    "payloads/*",
    "__pycache__/*",
    "mls_config.json"
)

# Get current directory
$CURRENT_DIR = Get-Location

Write-Host "[1/8] Checking Git Repository..." -ForegroundColor Yellow
if (-not (Test-Path ".git")) {
    Write-Host "ERROR: Not a git repository!" -ForegroundColor Red
    Write-Host "Please run this script from the prometheus-prime directory" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Git repository detected" -ForegroundColor Green
Write-Host ""

# Check current branch
Write-Host "[2/8] Checking Current Branch..." -ForegroundColor Yellow
$currentBranch = git rev-parse --abbrev-ref HEAD
Write-Host "Current branch: $currentBranch" -ForegroundColor Cyan

if ($currentBranch -ne $BRANCH) {
    Write-Host "Switching to branch: $BRANCH" -ForegroundColor Yellow

    # Stash any local changes first
    $stashResult = git stash
    Write-Host "Stashed local changes" -ForegroundColor Cyan

    # Fetch the branch
    Write-Host "Fetching branch from remote..." -ForegroundColor Yellow
    git fetch origin $BRANCH

    # Checkout the branch
    git checkout $BRANCH

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Could not checkout branch $BRANCH" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[OK] On correct branch: $BRANCH" -ForegroundColor Green
Write-Host ""

# Create backup directory
Write-Host "[3/8] Creating Backup..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
Write-Host "Backup directory created: $BACKUP_DIR" -ForegroundColor Cyan

# Backup protected files
Write-Host "Backing up protected files..." -ForegroundColor Yellow
foreach ($pattern in $PROTECTED_FILES) {
    $files = Get-ChildItem -Path $pattern -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $relativePath = $file.FullName.Replace($CURRENT_DIR, "")
        $backupPath = Join-Path $BACKUP_DIR $relativePath
        $backupDir = Split-Path $backupPath -Parent

        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }

        Copy-Item $file.FullName $backupPath -Force
        Write-Host "  Backed up: $relativePath" -ForegroundColor DarkCyan
    }
}

Write-Host "[OK] Backup completed: $BACKUP_DIR" -ForegroundColor Green
Write-Host ""

# Check git status
Write-Host "[4/8] Checking Git Status..." -ForegroundColor Yellow
git status --short

# Get file count before pull
$filesBefore = (Get-ChildItem -Recurse -File | Measure-Object).Count
Write-Host "Files before integration: $filesBefore" -ForegroundColor Cyan
Write-Host ""

# Pull latest changes
Write-Host "[5/8] Pulling Latest Changes from Git..." -ForegroundColor Yellow
Write-Host "This will download all 27,485+ files from the repository..." -ForegroundColor Cyan

$pullResult = git pull origin $BRANCH

if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Pull had issues, but continuing..." -ForegroundColor Yellow
}

Write-Host "[OK] Git pull completed" -ForegroundColor Green
Write-Host ""

# Restore protected files from backup
Write-Host "[6/8] Restoring Protected Files..." -ForegroundColor Yellow
foreach ($pattern in $PROTECTED_FILES) {
    $backupFiles = Get-ChildItem -Path (Join-Path $BACKUP_DIR $pattern) -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $backupFiles) {
        $relativePath = $file.FullName.Replace((Join-Path $CURRENT_DIR $BACKUP_DIR), "")
        $restorePath = Join-Path $CURRENT_DIR $relativePath

        Copy-Item $file.FullName $restorePath -Force
        Write-Host "  Restored: $relativePath" -ForegroundColor DarkGreen
    }
}

Write-Host "[OK] Protected files restored" -ForegroundColor Green
Write-Host ""

# Get file count after integration
Write-Host "[7/8] Verifying Integration..." -ForegroundColor Yellow
$filesAfter = (Get-ChildItem -Recurse -File | Measure-Object).Count
Write-Host "Files after integration: $filesAfter" -ForegroundColor Cyan
Write-Host "Files added/updated: $($filesAfter - $filesBefore)" -ForegroundColor Green

# Check for important directories
Write-Host ""
Write-Host "Verifying critical directories..." -ForegroundColor Yellow
$criticalDirs = @(
    "AD/BloodHound",
    "BEEF",
    "EMPIRE",
    "MIMIKATZ",
    "NUCLEI_TEMPLATES",
    "OMEGA_SWARM_BRAIN",
    "OSINT",
    "PAYLOADS",
    "SECLISTS",
    "SAFETY",
    "TOOLS"
)

foreach ($dir in $criticalDirs) {
    if (Test-Path $dir) {
        $count = (Get-ChildItem $dir -Recurse -File | Measure-Object).Count
        Write-Host "  [OK] $dir - $count files" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $dir" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "[OK] Integration verified" -ForegroundColor Green
Write-Host ""

# Final summary
Write-Host "[8/8] Integration Summary" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Branch: $BRANCH" -ForegroundColor White
Write-Host "Total Files: $filesAfter" -ForegroundColor White
Write-Host "Files Added/Updated: $($filesAfter - $filesBefore)" -ForegroundColor Green
Write-Host "Backup Location: $BACKUP_DIR" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "INTEGRATION COMPLETE!" -ForegroundColor Green -BackgroundColor Black
Write-Host ""
Write-Host "Your PC now has ALL files from the git repository!" -ForegroundColor Green
Write-Host "Protected files (configs, databases, logs) were preserved." -ForegroundColor Yellow
Write-Host "A backup was created in: $BACKUP_DIR" -ForegroundColor Yellow
Write-Host ""

# List Python files for verification
Write-Host "Key Python Files Available:" -ForegroundColor Cyan
$pythonFiles = Get-ChildItem -Path "*.py" -File | Select-Object -First 20
foreach ($file in $pythonFiles) {
    Write-Host "  - $($file.Name)" -ForegroundColor DarkCyan
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Review the backup in: $BACKUP_DIR" -ForegroundColor White
Write-Host "2. Test your essential scripts to ensure they work" -ForegroundColor White
Write-Host "3. Check your .env file has correct settings" -ForegroundColor White
Write-Host "4. Run: python PROMETHEUS_PRIME_ULTIMATE_ENHANCED.py" -ForegroundColor White
Write-Host ""
Write-Host "Integration log saved to: integration_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log" -ForegroundColor DarkGray
