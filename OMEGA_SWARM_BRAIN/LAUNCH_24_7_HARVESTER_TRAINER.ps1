#!/usr/bin/env pwsh
<#
╔══════════════════════════════════════════════════════════════════╗
║   OMEGA HARVESTER-TRAINER NETWORK - 24/7 LAUNCHER               ║
║   560 Harvesters + 150 Trainers = 710 Agent Network            ║
╚══════════════════════════════════════════════════════════════════╝

LAUNCHES:
✅ 560 Online Harvesters (knowledge acquisition)
✅ 150 Continuous Trainers (Echo training)
✅ Knowledge Pipeline (harvest → train)
✅ Omega Brain Integration

Authority Level: 11.0 - Commander Bobby Don McWilliams II
#>

# ══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════

$OMEGA_DIR = "P:\ECHO_PRIME\OMEGA_SWARM_BRAIN"
$HARVESTER_DIR = "P:\ECHO_PRIME\Harvesters"
$TRAINER_DIR = "P:\ECHO_PRIME\Trainers"
$PYTHON_VENV = "P:\.venv\Scripts\python.exe"

# Check if virtual environment exists
if (-not (Test-Path $PYTHON_VENV)) {
    $PYTHON_VENV = "python"
    Write-Warning "Virtual environment not found, using system Python"
}

# ══════════════════════════════════════════════════════════════════
# STARTUP BANNER
# ══════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   OMEGA HARVESTER-TRAINER NETWORK - 24/7 OPERATIONS              ║" -ForegroundColor Cyan
Write-Host "║   560 Harvesters + 150 Trainers = 710 Agents                     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ══════════════════════════════════════════════════════════════════
# PRE-FLIGHT CHECKS
# ══════════════════════════════════════════════════════════════════

Write-Host "🔍 PRE-FLIGHT CHECKS..." -ForegroundColor Yellow
Write-Host ""

# Check directories
Write-Host "[1/5] Checking directories..." -ForegroundColor White
$directories = @($OMEGA_DIR, $HARVESTER_DIR, $TRAINER_DIR)
foreach ($dir in $directories) {
    if (Test-Path $dir) {
        Write-Host "  ✅ $dir" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $dir NOT FOUND" -ForegroundColor Red
        exit 1
    }
}

# Check Python
Write-Host "[2/5] Checking Python..." -ForegroundColor White
try {
    $pythonVersion = & $PYTHON_VENV --version 2>&1
    Write-Host "  ✅ $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Python not available" -ForegroundColor Red
    exit 1
}

# Check Omega Brain modules
Write-Host "[3/5] Checking Omega Brain modules..." -ForegroundColor White
$omegaModules = @(
    "omega_core.py",
    "omega_trinity.py",
    "omega_integration.py",
    "omega_harvester_trainer_network.py"
)
foreach ($module in $omegaModules) {
    $modulePath = Join-Path $OMEGA_DIR $module
    if (Test-Path $modulePath) {
        Write-Host "  ✅ $module" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️ $module not found" -ForegroundColor Yellow
    }
}

# Check Harvester modules
Write-Host "[4/5] Checking Harvester modules..." -ForegroundColor White
$harvesterCount = (Get-ChildItem -Path $HARVESTER_DIR -Filter "*_harvester.py" -File).Count
Write-Host "  ✅ Found $harvesterCount harvester modules" -ForegroundColor Green

# Check Trainer modules
Write-Host "[5/5] Checking Trainer modules..." -ForegroundColor White
$trainerCount = (Get-ChildItem -Path $TRAINER_DIR -Filter "*_trainer.py" -File).Count
Write-Host "  ✅ Found $trainerCount trainer modules" -ForegroundColor Green

Write-Host ""
Write-Host "✅ PRE-FLIGHT CHECKS COMPLETE" -ForegroundColor Green
Write-Host ""

# ══════════════════════════════════════════════════════════════════
# LAUNCH OPTIONS
# ══════════════════════════════════════════════════════════════════

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "LAUNCH OPTIONS:" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "[1] 🔥 Launch FULL 24/7 Network (560H + 150T)" -ForegroundColor Yellow
Write-Host "[2] 🌐 Launch Harvesters Only (560 agents)" -ForegroundColor Cyan
Write-Host "[3] 🎓 Launch Trainers Only (150 agents)" -ForegroundColor Magenta
Write-Host "[4] ⚡ Launch Knowledge Pipeline Only" -ForegroundColor Green
Write-Host "[5] 📊 View Network Status" -ForegroundColor Blue
Write-Host "[6] 🛑 Exit" -ForegroundColor Red
Write-Host ""

$choice = Read-Host "Select option [1-6]"

# ══════════════════════════════════════════════════════════════════
# LAUNCH FUNCTIONS
# ══════════════════════════════════════════════════════════════════

function Launch-Full-Network {
    Write-Host ""
    Write-Host "🔥 LAUNCHING FULL 24/7 NETWORK..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ⚡ 560 Harvesters coming ONLINE..." -ForegroundColor Cyan
    Write-Host "  ⚡ 150 Trainers coming ONLINE..." -ForegroundColor Magenta
    Write-Host "  ⚡ Knowledge Pipeline ACTIVATING..." -ForegroundColor Green
    Write-Host "  ⚡ Omega Brain connection ESTABLISHING..." -ForegroundColor Blue
    Write-Host ""
    
    Set-Location $OMEGA_DIR
    & $PYTHON_VENV omega_harvester_trainer_network.py
}

function Launch-Harvesters-Only {
    Write-Host ""
    Write-Host "🌐 LAUNCHING HARVESTERS ONLY..." -ForegroundColor Cyan
    Write-Host ""
    
    # Create harvesters-only script
    $scriptContent = @"
import asyncio
import sys
sys.path.insert(0, '$OMEGA_DIR')
from omega_harvester_trainer_network import HarvesterNetwork

async def main():
    network = HarvesterNetwork()
    await network.initialize_harvesters(560)
    await network.bring_all_online()
    await network.continuous_harvest()

asyncio.run(main())
"@
    
    $scriptPath = Join-Path $OMEGA_DIR "temp_harvesters_only.py"
    $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    
    Set-Location $OMEGA_DIR
    & $PYTHON_VENV $scriptPath
    
    Remove-Item $scriptPath -ErrorAction SilentlyContinue
}

function Launch-Trainers-Only {
    Write-Host ""
    Write-Host "🎓 LAUNCHING TRAINERS ONLY..." -ForegroundColor Magenta
    Write-Host ""
    
    # Create trainers-only script
    $scriptContent = @"
import asyncio
import sys
sys.path.insert(0, '$OMEGA_DIR')
from omega_harvester_trainer_network import TrainerNetwork

async def main():
    network = TrainerNetwork()
    await network.initialize_trainers(150)
    await network.bring_all_online()
    await network.continuous_training()

asyncio.run(main())
"@
    
    $scriptPath = Join-Path $OMEGA_DIR "temp_trainers_only.py"
    $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    
    Set-Location $OMEGA_DIR
    & $PYTHON_VENV $scriptPath
    
    Remove-Item $scriptPath -ErrorAction SilentlyContinue
}

function View-Network-Status {
    Write-Host ""
    Write-Host "📊 NETWORK STATUS..." -ForegroundColor Blue
    Write-Host ""
    
    # Create status script
    $scriptContent = @"
import asyncio
import sys
import json
sys.path.insert(0, '$OMEGA_DIR')
from omega_harvester_trainer_network import HarvesterTrainerBrainIntegration

async def main():
    system = HarvesterTrainerBrainIntegration()
    await system.initialize()
    
    status = system.get_comprehensive_status()
    print(json.dumps(status, indent=2))

asyncio.run(main())
"@
    
    $scriptPath = Join-Path $OMEGA_DIR "temp_status.py"
    $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    
    Set-Location $OMEGA_DIR
    & $PYTHON_VENV $scriptPath
    
    Remove-Item $scriptPath -ErrorAction SilentlyContinue
    
    Write-Host ""
    Read-Host "Press Enter to continue"
    & $PSCommandPath  # Relaunch menu
}

# ══════════════════════════════════════════════════════════════════
# EXECUTE CHOICE
# ══════════════════════════════════════════════════════════════════

switch ($choice) {
    "1" { Launch-Full-Network }
    "2" { Launch-Harvesters-Only }
    "3" { Launch-Trainers-Only }
    "4" { 
        Write-Host ""
        Write-Host "⚡ Knowledge Pipeline requires both Harvesters and Trainers" -ForegroundColor Yellow
        Write-Host "   Please use option [1] to launch full network" -ForegroundColor Yellow
        Write-Host ""
        Read-Host "Press Enter to continue"
        & $PSCommandPath
    }
    "5" { View-Network-Status }
    "6" { 
        Write-Host ""
        Write-Host "🛑 Exiting..." -ForegroundColor Red
        Write-Host ""
        exit 0
    }
    default {
        Write-Host ""
        Write-Host "❌ Invalid option. Please select 1-6" -ForegroundColor Red
        Write-Host ""
        Start-Sleep -Seconds 2
        & $PSCommandPath  # Relaunch menu
    }
}

# ══════════════════════════════════════════════════════════════════
# SHUTDOWN HANDLER
# ══════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Network operations terminated" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
