#!/bin/bash
#
# 🔥 ECHO PRIME OMEGA - Master GUI Launcher
# Authority Level: 11.0
#

echo "=========================================="
echo "🔥 ECHO PRIME OMEGA - Master Control"
echo "   Authority Level: 11.0"
echo "=========================================="
echo ""

# Check dependencies
if ! python3 -c "import flask" 2>/dev/null; then
    echo "❌ Flask not installed. Installing..."
    pip3 install flask flask-socketio python-socketio
fi

echo "✅ Starting Echo Prime Master GUI..."
echo ""
echo "📋 Integrated Systems:"
echo "   ⚔️  Prometheus Prime"
echo "   🐝 Omega Swarm Brain"
echo "   💾 Memory System"
echo "   🔐 MLS Server"
echo "   🧠 Omniscience Intelligence"
echo "   👑 Sovereign Control"
echo ""
echo "🌐 Server: http://localhost:5000"
echo "⚠️  AUTHORIZATION REQUIRED"
echo ""
echo "Press Ctrl+C to stop"
echo "=========================================="
echo ""

# Launch
python3 echo_prime_master_gui.py
