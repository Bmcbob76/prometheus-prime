# PROMETHEUS PRIME - Windows Installation Script
# Deploys to P:\ECHO_PRIME\prometheus_prime_new
# Authority Level: 11.0

param(
    [string]$SourcePath = ".",
    [string]$TargetDrive = "P:",
    [string]$TargetPath = "ECHO_PRIME\prometheus_prime_new"
)

Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 79) -ForegroundColor Cyan
Write-Host "🔥 PROMETHEUS PRIME - WINDOWS DEPLOYMENT" -ForegroundColor Yellow
Write-Host ("=" * 80) -ForegroundColor Cyan

$FullTargetPath = Join-Path $TargetDrive $TargetPath

Write-Host "`n📊 DEPLOYMENT CONFIGURATION" -ForegroundColor Green
Write-Host "   Source: $SourcePath"
Write-Host "   Target: $FullTargetPath"
Write-Host "   Authority Level: 11.0"
Write-Host "   Total Tools: 282 MCP tools"

# Check if target drive exists
if (-not (Test-Path $TargetDrive)) {
    Write-Host "`n❌ ERROR: Drive $TargetDrive not found!" -ForegroundColor Red
    Write-Host "   Please ensure the P: drive is mounted and accessible." -ForegroundColor Yellow
    exit 1
}

Write-Host "`n✅ Target drive $TargetDrive exists" -ForegroundColor Green

# Create target directory
Write-Host "`n📁 Creating target directory..." -ForegroundColor Cyan
if (-not (Test-Path $FullTargetPath)) {
    New-Item -ItemType Directory -Path $FullTargetPath -Force | Out-Null
    Write-Host "   ✅ Created: $FullTargetPath" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Directory already exists: $FullTargetPath" -ForegroundColor Yellow
    $response = Read-Host "   Overwrite? (Y/N)"
    if ($response -ne "Y") {
        Write-Host "`n❌ Installation cancelled by user" -ForegroundColor Red
        exit 0
    }
}

# Copy files
Write-Host "`n📦 Copying files..." -ForegroundColor Cyan

$FilesToCopy = @(
    "prometheus_complete.py",
    "PROMETHEUS_CAPABILITY_REGISTRY.py",
    "mcp_server.py",
    "mcp_server_complete.py",
    "requirements.txt",
    "PROMETHEUS_MCP_TOOLS_COMPLETE.txt",
    "demo_autonomous.py",
    "launch_autonomous.py",
    "test_mcp_tool.py",
    ".env.example"
)

$DirectoriesToCopy = @(
    "tools",
    "capabilities",
    "modules",
    "specialized_toolkits",
    "ULTIMATE_CAPABILITIES",
    "AUTONOMY",
    "src",
    "OMEGA_SWARM_BRAIN"
)

# Copy individual files
foreach ($file in $FilesToCopy) {
    $sourcePath = Join-Path $SourcePath $file
    if (Test-Path $sourcePath) {
        Copy-Item -Path $sourcePath -Destination $FullTargetPath -Force
        Write-Host "   ✅ $file" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  $file (not found)" -ForegroundColor Yellow
    }
}

# Copy directories recursively
foreach ($dir in $DirectoriesToCopy) {
    $sourcePath = Join-Path $SourcePath $dir
    $destPath = Join-Path $FullTargetPath $dir
    if (Test-Path $sourcePath) {
        Copy-Item -Path $sourcePath -Destination $FullTargetPath -Recurse -Force
        $fileCount = (Get-ChildItem -Path $sourcePath -Recurse -File).Count
        Write-Host "   ✅ $dir\ ($fileCount files)" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  $dir\ (not found)" -ForegroundColor Yellow
    }
}

# Create .env file if it doesn't exist
$envPath = Join-Path $FullTargetPath ".env"
if (-not (Test-Path $envPath)) {
    Write-Host "`n🔑 Creating .env configuration file..." -ForegroundColor Cyan
    $envContent = @"
# PROMETHEUS PRIME CONFIGURATION
# Authority Level: 11.0

# API Keys (REQUIRED for autonomous operation)
ANTHROPIC_API_KEY=your_anthropic_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
GOOGLE_API_KEY=your_google_api_key_here
COHERE_API_KEY=your_cohere_api_key_here
ELEVENLABS_API_KEY=your_elevenlabs_api_key_here

# Database Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
MYSQL_HOST=localhost
MYSQL_PORT=3306
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

# Memory System
MEMORY_ROOT=M:\MEMORY_ORCHESTRATION

# Authority Level
AUTHORITY_LEVEL=11.0
OPERATOR=Commander Bobby Don McWilliams II

# Safety Settings
SAFETY_LEVEL=maximum
ROE_COMPLIANCE=enabled
AUDIT_LOGGING=enabled
"@
    Set-Content -Path $envPath -Value $envContent
    Write-Host "   ✅ Created .env file (PLEASE CONFIGURE API KEYS!)" -ForegroundColor Green
}

# Create installation summary
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "✅ INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host ("=" * 80) -ForegroundColor Cyan

Write-Host "`n📊 INSTALLATION SUMMARY" -ForegroundColor Yellow
Write-Host "   Location: $FullTargetPath"
Write-Host "   MCP Tools: 282 capabilities across 6 categories"
Write-Host "   Configuration: .env file created (CONFIGURE API KEYS!)"

Write-Host "`n🚀 NEXT STEPS:" -ForegroundColor Yellow
Write-Host "   1. Configure API keys in: $FullTargetPath\.env"
Write-Host "   2. Install Python dependencies:"
Write-Host "      cd $FullTargetPath"
Write-Host "      pip install -r requirements.txt"
Write-Host "   3. Test MCP tools:"
Write-Host "      python test_mcp_tool.py"
Write-Host "   4. Launch autonomous mode:"
Write-Host "      python demo_autonomous.py"
Write-Host "   5. Start MCP server for Claude Desktop:"
Write-Host "      python mcp_server.py"

Write-Host "`n📝 DOCUMENTATION:" -ForegroundColor Yellow
Write-Host "   Full tool list: $FullTargetPath\PROMETHEUS_MCP_TOOLS_COMPLETE.txt"
Write-Host "   Registry: $FullTargetPath\PROMETHEUS_CAPABILITY_REGISTRY.py"

Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "🔥 PROMETHEUS PRIME IS READY FOR DEPLOYMENT" -ForegroundColor Green
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host ""
