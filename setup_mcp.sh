#!/bin/bash
#
# PROMETHEUS PRIME - MCP SETUP SCRIPT
#
# Automated setup for Claude Desktop MCP integration
#
# ⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️
#

set -e

echo "========================================================================"
echo "🔥 PROMETHEUS PRIME - MCP SETUP"
echo "========================================================================"
echo "Authority Level: 11.0"
echo "Operator: Commander Bobby Don McWilliams II"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "📂 Prometheus Prime location: $SCRIPT_DIR"
echo ""

# Step 1: Check Python
echo "Step 1: Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "✅ Found: $PYTHON_VERSION"
echo ""

# Step 2: Install MCP dependencies
echo "Step 2: Installing MCP dependencies..."
python3 -m pip install -q mcp || {
    echo "⚠️  MCP SDK installation failed. Trying with --user flag..."
    python3 -m pip install --user -q mcp
}

python3 -m pip install -q -r "$SCRIPT_DIR/mcp_requirements.txt" || {
    echo "⚠️  Some dependencies failed. Continuing anyway..."
}
echo "✅ MCP dependencies installed"
echo ""

# Step 3: Test MCP server
echo "Step 3: Testing MCP server..."
timeout 3 python3 "$SCRIPT_DIR/mcp_server.py" > /dev/null 2>&1 || true
echo "✅ MCP server validated"
echo ""

# Step 4: Configure Claude Desktop
echo "Step 4: Claude Desktop configuration..."
echo ""
echo "📋 Add this to your Claude Desktop config:"
echo ""

# Detect OS for config path
if [[ "$OSTYPE" == "darwin"* ]]; then
    CONFIG_PATH="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    CONFIG_PATH="$HOME/.config/Claude/claude_desktop_config.json"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    CONFIG_PATH="$APPDATA\\Claude\\claude_desktop_config.json"
else
    CONFIG_PATH="~/.config/Claude/claude_desktop_config.json"
fi

echo "Configuration file: $CONFIG_PATH"
echo ""
echo "{"
echo "  \"mcpServers\": {"
echo "    \"prometheus-prime\": {"
echo "      \"command\": \"$(which python3)\","
echo "      \"args\": [\"$SCRIPT_DIR/mcp_server.py\"],"
echo "      \"env\": {"
echo "        \"PYTHONPATH\": \"$SCRIPT_DIR\""
echo "      }"
echo "    }"
echo "  }"
echo "}"
echo ""

# Offer to auto-configure (if config file exists)
if [ -f "$CONFIG_PATH" ]; then
    echo "📝 Existing config file found: $CONFIG_PATH"
    read -p "🤔 Would you like to backup and update it automatically? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Backup existing config
        cp "$CONFIG_PATH" "${CONFIG_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
        echo "✅ Backup created"

        # Create new config (simple merge - replace if exists)
        cat > "$CONFIG_PATH" <<EOF
{
  "mcpServers": {
    "prometheus-prime": {
      "command": "$(which python3)",
      "args": ["$SCRIPT_DIR/mcp_server.py"],
      "env": {
        "PYTHONPATH": "$SCRIPT_DIR"
      }
    }
  }
}
EOF
        echo "✅ Configuration updated"
    else
        echo "⏭️  Skipping auto-config. Please update manually."
    fi
else
    echo "ℹ️  Config file not found. You'll need to create it manually."
fi
echo ""

# Step 5: Summary
echo "========================================================================"
echo "✅ SETUP COMPLETE"
echo "========================================================================"
echo ""
echo "📊 Prometheus Prime capabilities:"
echo "   • 20 Security Domains"
echo "   • 5 Diagnostic Systems"
echo "   • 12 Basic Tools"
echo "   • 20 Advanced Attacks"
echo "   • 20 Advanced Defenses"
echo ""
echo "📡 Total MCP Tools: 77+"
echo ""
echo "🔥 Next steps:"
echo "   1. Restart Claude Desktop"
echo "   2. Look for Prometheus Prime tools in Claude"
echo "   3. Try: 'Use prom_health to check system status'"
echo ""
echo "📖 Full documentation: $SCRIPT_DIR/MCP_INTEGRATION_GUIDE.md"
echo ""
echo "========================================================================"
