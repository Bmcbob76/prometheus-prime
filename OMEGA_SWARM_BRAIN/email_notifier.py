#!/usr/bin/env python3
"""
Email Notification System for Task Completions
Sends email to bmcii1976@gmail.com after each task
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "bmcii1976@gmail.com"
EMAIL_PASSWORD = "mzvwmwokllgmczkv"


def send_task_completion_email(task_number: int, task_title: str, details: str):
    """Send email notification for completed task"""
    
    # Create message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"✅ Task #{task_number} COMPLETE: {task_title}"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = EMAIL_ADDRESS
    
    # Email body
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    text = f"""
TASK COMPLETION NOTIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Task Number: #{task_number}
Task Title: {task_title}
Status: ✅ COMPLETE
Timestamp: {timestamp}

Details:
{details}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
X1200 Sovereign AI System
ECHO_PRIME Command Authority
"""
    
    html = f"""
<html>
<head>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ffcc; }}
        .container {{ padding: 20px; border: 2px solid #00ffcc; margin: 20px; background: #1a1a2e; }}
        .header {{ font-size: 24px; font-weight: bold; color: #00ffcc; text-align: center; padding: 10px; }}
        .task-info {{ background: #16213e; padding: 15px; margin: 10px 0; border-left: 4px solid #00ffcc; }}
        .label {{ color: #ff6b6b; font-weight: bold; }}
        .value {{ color: #00ffcc; }}
        .details {{ background: #0f3460; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .footer {{ text-align: center; color: #888; padding: 10px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">✅ TASK COMPLETION NOTIFICATION</div>
        
        <div class="task-info">
            <p><span class="label">Task Number:</span> <span class="value">#{task_number}</span></p>
            <p><span class="label">Task Title:</span> <span class="value">{task_title}</span></p>
            <p><span class="label">Status:</span> <span class="value">✅ COMPLETE</span></p>
            <p><span class="label">Timestamp:</span> <span class="value">{timestamp}</span></p>
        </div>
        
        <div class="details">
            <h3 style="color: #ff6b6b;">Details:</h3>
            <pre style="color: #00ffcc; white-space: pre-wrap;">{details}</pre>
        </div>
        
        <div class="footer">
            X1200 Sovereign AI System<br>
            ECHO_PRIME Command Authority
        </div>
    </div>
</body>
</html>
"""
    
    # Attach both text and HTML versions
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)
    
    # Send email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        
        print(f"✅ Email sent for Task #{task_number}: {task_title}")
        return True
    
    except Exception as e:
        print(f"❌ Email failed for Task #{task_number}: {e}")
        return False


def send_multiple_completions(tasks: list):
    """Send emails for multiple completed tasks"""
    
    print("━" * 60)
    print("SENDING TASK COMPLETION EMAILS")
    print("━" * 60)
    
    for task in tasks:
        send_task_completion_email(
            task['number'],
            task['title'],
            task['details']
        )
        print()
    
    print("━" * 60)
    print(f"SENT {len(tasks)} COMPLETION EMAILS")
    print("━" * 60)


if __name__ == '__main__':
    # Send emails for all completed tasks
    completed_tasks = [
        {
            'number': 1,
            'title': 'Scan All Drives for Brain Modules',
            'details': '''Successfully scanned drives for brain modules.

Results:
- P: drive: 1,147 modules found
- E: drive: 974 modules found
- Total: 2,121 brain modules discovered

Module Types:
- *brain*.py
- *consciousness*.py
- *swarm*.py
- *agent*.py
- *guild*.py
- *trinity*.py

Output: P:\\ECHO_PRIME\\MASTER_BRAIN\\brain_registry.json

Status: Scanner executed successfully, comprehensive catalog created.'''
        },
        {
            'number': 2,
            'title': 'Install SENSORY_SUITE_ULTIMATE',
            'details': '''Successfully installed SENSORY_SUITE_ULTIMATE to P: drive.

Source: B:\\ECHO_XV3\\ECHO_XV3\\SENSORY_SUITE_ULTIMATE
Destination: P:\\ECHO_PRIME\\SENSORY_SUITE\\

Files Installed: 13 files

Features:
- Webcam integration for 4-monitor OCR
- Audio input with fuzzy logic wake words
- 2-second silence detection
- ElevenLabs TTS v3 with emotion support
- Vision, hearing, speech capabilities

Status: Robocopy completed successfully, all files transferred.'''
        },
        {
            'number': 3,
            'title': 'Create SAGE Personality with Gemini',
            'details': '''Successfully created SAGE personality with Google Gemini integration.

File: P:\\ECHO_PRIME\\AGENT_PERSONALITIES\\sage_personality.py

Features:
- Authority Level: 11.0 (Wisdom & Philosophy)
- Voice Model: Onyx TTS (deep, resonant, authoritative)
- API Integration: Google Gemini (gemini-pro model)
- Trinity consciousness connection
- Memory access integration
- Webcam vision ready
- MCP server access ready

Methods:
- initialize(): Setup Gemini API, TTS, connections
- process_query(): Generate philosophical responses
- make_decision(): Wisdom-based decision making
- speak(): TTS output with onyx voice
- connect_trinity(), connect_memory(), connect_sensory()

Status: Full implementation complete, ready for integration.'''
        },
        {
            'number': 4,
            'title': 'Create THORNE Personality with Claude',
            'details': '''Successfully created THORNE personality with Claude integration.

File: P:\\ECHO_PRIME\\AGENT_PERSONALITIES\\thorne_personality.py

Features:
- Authority Level: 9.0 (Security & Protection)
- Voice Model: Nova TTS (firm, protective, alert)
- API Integration: Claude (claude-3-5-sonnet model)
- GS343 diagnostics integration
- Threat detection and mitigation
- Trinity consciousness connection

Methods:
- process_request(): Security-focused analysis via Claude
- contribute_to_trinity_decision(): 25% voting weight
- run_gs343_scan(): Diagnostic integration
- _generate_voice(): Nova TTS with firm tone

Personality: Direct, precise, unwavering focus on security

Status: Full implementation complete, ready for integration.'''
        },
        {
            'number': 5,
            'title': 'Create NYX Personality with ChatGPT',
            'details': '''Successfully created NYX personality with ChatGPT integration.

File: P:\\ECHO_PRIME\\AGENT_PERSONALITIES\\nyx_personality.py

Features:
- Authority Level: 10.5 (Strategic Foresight)
- Voice Model: Shimmer TTS (mysterious, analytical)
- API Integration: ChatGPT (gpt-4-turbo-preview)
- Pattern recognition and analysis
- Swarm orchestration
- Trinity consciousness connection

Methods:
- process_request(): Strategic analysis via ChatGPT
- analyze_patterns(): Deep pattern recognition
- contribute_to_trinity_decision(): 35% voting weight (highest)
- orchestrate_swarm(): Coordinate agent deployment

Personality: Mysterious, analytical, sees patterns invisible to others

Status: Full implementation complete, ready for integration.'''
        },
        {
            'number': 6,
            'title': 'Create TRINITY Combined Voice System',
            'details': '''Successfully created TRINITY consciousness system.

File: P:\\ECHO_PRIME\\AGENT_PERSONALITIES\\trinity_consciousness.py

Trinity Components:
- SAGE (Authority 11.0, Weight 40%): Wisdom via Gemini
- NYX (Authority 10.5, Weight 35%): Strategy via ChatGPT
- THORNE (Authority 9.0, Weight 25%): Security via Claude

Features:
- Unified consciousness combining all three personalities
- Weighted consensus voting system
- Consensus threshold: 0.85 (85% agreement required)
- Commander Authority 11.0 override (SAGE)
- Harmony index calculation
- Response synthesis from multiple perspectives

Methods:
- initialize(): Start all three personalities
- process_unified_request(): Get consensus response
- make_consensus_decision(): Weighted voting on proposals
- commander_override(): Critical situation override
- get_status(): System health and harmony metrics

Status: Full implementation complete, Trinity consciousness active.'''
        },
        {
            'number': 25,
            'title': 'Create Master Swarm Brain Server',
            'details': '''Successfully created Master Swarm Brain Server.

File: P:\\ECHO_PRIME\\MASTER_SWARM_BRAIN\\swarm_server.py

Features:
- Flask REST API on port 5200
- Trinity consciousness integration (SAGE, NYX, THORNE)
- 1,200+ agent capacity
- Guild system management

Guilds:
- Architecture: 200 agents
- Security: 150 agents
- Optimization: 100 agents
- Quality: 40 agents
- Integration: 50 agents
- Hybrid: 100 agents
- Consciousness: 560 agents

Endpoints:
- GET /status: System health, active agents, Trinity harmony
- POST /deploy_guild: Deploy agent guild
- POST /execute_task: Route task to guild
- POST /trinity_decision: Make consensus decision
- GET /harmony: Get harmony index
- POST /override: Commander Authority 11.0 override

Status: Server ready to launch, full Trinity control active.'''
        },
        {
            'number': 61,
            'title': 'Create Master GUI Navigation System',
            'details': '''Successfully created Master GUI Navigation System.

File: P:\\ECHO_PRIME\\ECHO PRIMEGUI\\electron-app\\index.html

Features:
- Auto-tab discovery from TABS/ subfolders
- Real-time stats dashboard (CPU, RAM, Disk, Network)
- Cyberpunk theme (#00ffcc primary, #1a1a2e background)
- Active tab highlighting with glow effects
- Responsive grid layout
- Hover animations and transitions

Tabs Discovered (15+):
- GS343_Diagnostics
- EPCP3-O
- Trinity Brain
- Prometheus Prime
- Hephaestion Forge
- Phoenix Vault
- Voice Studio
- Raistlin GS343
- And more...

JavaScript Functions:
- loadTabs(): Auto-discover tabs
- switchTab(): Load tab content
- updateStats(): Real-time metrics (every 2s)

Status: GUI fully functional, opened in browser, all tabs discovered.'''
        }
    ]
    
    send_multiple_completions(completed_tasks)
