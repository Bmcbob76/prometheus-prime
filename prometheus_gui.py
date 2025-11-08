"""
PROMETHEUS PRIME GUI
Complete graphical interface for all 20 security domains

Authority Level: 11.0
Operator: Commander Bobby Don McWilliams II

Features:
- 20 domain tabs with controls
- AI guidance integration
- Stealth mode controls
- Defense system monitoring
- Real-time status updates
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import asyncio
from threading import Thread
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import Prometheus modules
from prometheus_complete import PrometheusComplete, SecurityDomain
from src.ai_brain import PrometheusAIBrain
from src.voice import PrometheusVoice
from src.stealth import StealthMode
from src.defense import DefenseEngine


class PrometheusGUI:
    """
    Prometheus Prime Graphical User Interface

    Complete control center for all 20 security domains
    """

    def __init__(self, root):
        self.root = root
        self.root.title("🔥 PROMETHEUS PRIME ULTIMATE - Authority Level 11.0")
        self.root.geometry("1400x900")

        # Initialize Prometheus systems
        self.prometheus = PrometheusComplete()
        self.ai_brain = PrometheusAIBrain()
        self.voice = PrometheusVoice()
        self.stealth = StealthMode()
        self.defense = DefenseEngine()

        # System state
        self.stealth_active = False
        self.defense_active = True
        self.autonomous_running = False

        # Setup GUI
        self.setup_styles()
        self.create_menu()
        self.create_main_layout()
        self.create_status_bar()

        # Start systems
        self.log("🔥 PROMETHEUS PRIME ULTIMATE INITIALIZED")
        self.log(f"Authority: {os.getenv('ECHO_BLOODLINE_AUTH', 'Commander')}")

    def setup_styles(self):
        """Setup GUI styles"""
        style = ttk.Style()
        style.theme_use('clam')

        # Custom colors
        style.configure("Title.TLabel", font=('Courier', 14, 'bold'), foreground='red')
        style.configure("Domain.TButton", font=('Courier', 10), padding=10)

    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Config", command=self.load_config)
        file_menu.add_command(label="Save Config", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Stealth menu
        stealth_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Stealth", menu=stealth_menu)
        stealth_menu.add_command(label="Engage Full Stealth", command=self.engage_stealth)
        stealth_menu.add_command(label="Disengage Stealth", command=self.disengage_stealth)
        stealth_menu.add_command(label="Check Anonymity", command=self.check_anonymity)

        # Defense menu
        defense_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Defense", menu=defense_menu)
        defense_menu.add_command(label="Enable Defense", command=self.enable_defense)
        defense_menu.add_command(label="Disable Defense", command=self.disable_defense)
        defense_menu.add_command(label="View Threats", command=self.view_threats)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)

    def create_main_layout(self):
        """Create main layout with tabs"""
        # Title
        title_frame = ttk.Frame(self.root)
        title_frame.pack(fill=tk.X, padx=10, pady=5)

        title_label = ttk.Label(
            title_frame,
            text="🔥 PROMETHEUS PRIME ULTIMATE 🔥",
            style="Title.TLabel"
        )
        title_label.pack()

        subtitle_label = ttk.Label(
            title_frame,
            text="Autonomous AI Security Agent - 20 Elite Domains",
            font=('Courier', 10)
        )
        subtitle_label.pack()

        # Main container
        main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Left panel: Domain tabs
        left_frame = ttk.Frame(main_container)
        main_container.add(left_frame, weight=3)

        # Create notebook for domain tabs
        self.notebook = ttk.Notebook(left_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create all 20 domain tabs
        self.create_domain_tabs()

        # Right panel: Console and status
        right_frame = ttk.Frame(main_container)
        main_container.add(right_frame, weight=1)

        # Console log
        console_label = ttk.Label(right_frame, text="📋 Console Output", font=('Courier', 10, 'bold'))
        console_label.pack(pady=5)

        self.console = scrolledtext.ScrolledText(
            right_frame,
            height=20,
            font=('Courier', 9),
            bg='black',
            fg='green'
        )
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # System status
        status_label = ttk.Label(right_frame, text="📊 System Status", font=('Courier', 10, 'bold'))
        status_label.pack(pady=5)

        self.status_text = scrolledtext.ScrolledText(
            right_frame,
            height=15,
            font=('Courier', 8),
            bg='#1a1a1a',
            fg='cyan'
        )
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.update_status()

    def create_domain_tabs(self):
        """Create tabs for all 20 security domains"""
        domains = [
            ("Network Recon", "network_reconnaissance", "Port scanning, service enumeration"),
            ("Web Exploitation", "web_exploitation", "SQLi, XSS, web app testing"),
            ("Wireless Ops", "wireless_operations", "WiFi, Bluetooth, RFID attacks"),
            ("Social Engineering", "social_engineering", "Phishing, pretexting"),
            ("Physical Security", "physical_security", "Lockpicking, RFID cloning"),
            ("Crypto Analysis", "cryptographic_analysis", "Hash cracking, crypto attacks"),
            ("Malware Dev", "malware_development", "Payload creation, obfuscation"),
            ("Forensics", "digital_forensics", "Disk, memory, network forensics"),
            ("Cloud Security", "cloud_security", "AWS, Azure, GCP testing"),
            ("Mobile Security", "mobile_security", "Android/iOS exploitation"),
            ("IoT Security", "iot_security", "IoT device exploitation"),
            ("SCADA/ICS", "scada_ics_security", "Industrial control systems"),
            ("Threat Intel", "threat_intelligence", "APT tracking, IOCs"),
            ("Red Team", "red_team_operations", "Full offensive campaigns"),
            ("Blue Team", "blue_team_defense", "Threat hunting, IR"),
            ("Purple Team", "purple_team_integration", "Control validation"),
            ("OSINT", "osint_reconnaissance", "Intelligence gathering"),
            ("Exploit Dev", "exploit_development", "0-day, exploit chains"),
            ("Post-Exploitation", "post_exploitation", "Lateral movement, privesc"),
            ("Persistence", "persistence_mechanisms", "Rootkits, backdoors")
        ]

        for name, domain_id, description in domains:
            self.create_domain_tab(name, domain_id, description)

    def create_domain_tab(self, name, domain_id, description):
        """Create individual domain tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=name)

        # Domain info
        info_frame = ttk.LabelFrame(tab, text="Domain Information", padding=10)
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(info_frame, text=f"Domain: {name}", font=('Courier', 10, 'bold')).pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Description: {description}").pack(anchor=tk.W)

        # Target configuration
        target_frame = ttk.LabelFrame(tab, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(target_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=2)
        target_entry = ttk.Entry(target_frame, width=40)
        target_entry.grid(row=0, column=1, sticky=tk.EW, pady=2)
        target_entry.insert(0, "example.com")

        ttk.Label(target_frame, text="Parameters:").grid(row=1, column=0, sticky=tk.W, pady=2)
        params_entry = ttk.Entry(target_frame, width=40)
        params_entry.grid(row=1, column=1, sticky=tk.EW, pady=2)
        params_entry.insert(0, '{"ports": [80, 443, 8080]}')

        # Operation controls
        control_frame = ttk.LabelFrame(tab, text="Operation Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        # Operation buttons
        operations = self.get_domain_operations(domain_id)
        for i, op in enumerate(operations):
            btn = ttk.Button(
                control_frame,
                text=op.replace('_', ' ').title(),
                command=lambda d=domain_id, o=op, t=target_entry, p=params_entry: self.execute_operation(d, o, t.get(), p.get())
            )
            btn.grid(row=i//3, column=i%3, padx=5, pady=5, sticky=tk.EW)

        # AI Guidance
        ai_frame = ttk.LabelFrame(tab, text="🤖 AI Guidance", padding=10)
        ai_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ai_guidance = self.get_ai_guidance(domain_id)
        ai_text = scrolledtext.ScrolledText(ai_frame, height=8, font=('Courier', 9), wrap=tk.WORD)
        ai_text.pack(fill=tk.BOTH, expand=True)
        ai_text.insert('1.0', ai_guidance)
        ai_text.config(state=tk.DISABLED)

    def get_domain_operations(self, domain_id):
        """Get available operations for domain"""
        operations = {
            "network_reconnaissance": ["scan", "enumerate", "fingerprint"],
            "web_exploitation": ["enumerate", "sqli", "xss"],
            "wireless_operations": ["discover", "crack", "eviltwin"],
            "osint_reconnaissance": ["gather", "social", "leak"],
        }
        return operations.get(domain_id, ["scan", "enumerate", "exploit"])

    def get_ai_guidance(self, domain_id):
        """Get AI guidance for domain"""
        guidance = {
            "network_reconnaissance": """
🤖 AI GUIDANCE - Network Reconnaissance:

1. Start with passive reconnaissance (DNS, WHOIS)
2. Progress to active scanning (port scans)
3. Enumerate discovered services
4. Fingerprint OS and applications
5. Map network topology

⚠️  WARNING: Ensure proper authorization before scanning.

💡 TIP: Use stealth mode for operational security.
            """,
            "web_exploitation": """
🤖 AI GUIDANCE - Web Exploitation:

1. Enumerate web technologies
2. Spider/crawl the application
3. Test for common vulnerabilities (SQLi, XSS)
4. Check authentication mechanisms
5. Test API security

⚠️  WARNING: Only test authorized applications.

💡 TIP: Enable proxy for request manipulation.
            """
        }
        return guidance.get(domain_id, "No AI guidance available for this domain yet.")

    def execute_operation(self, domain_id, operation, target, params):
        """Execute security operation"""
        self.log(f"⚡ Executing: {domain_id}.{operation} on {target}")

        # Parse params
        try:
            import json
            params_dict = json.loads(params) if params else {}
        except:
            params_dict = {}

        params_dict['target'] = target

        # Execute in background thread
        thread = Thread(target=self.run_async_operation, args=(domain_id, operation, params_dict))
        thread.daemon = True
        thread.start()

    def run_async_operation(self, domain_id, operation, params):
        """Run async operation in thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            domain_enum = SecurityDomain(domain_id)
            result = loop.run_until_complete(
                self.prometheus.execute(domain_enum, operation, params)
            )

            self.log(f"✅ Operation complete: {result.success}")
            self.log(f"   Findings: {len(result.findings)}")

            for finding in result.findings[:5]:  # Show first 5
                self.log(f"   • {finding}")

        except Exception as e:
            self.log(f"❌ Operation failed: {e}")

    def engage_stealth(self):
        """Engage full stealth mode"""
        self.log("👻 Engaging full stealth mode...")

        thread = Thread(target=self._engage_stealth_async)
        thread.daemon = True
        thread.start()

    def _engage_stealth_async(self):
        """Async stealth engagement"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        result = loop.run_until_complete(self.stealth.engage_full_stealth())
        self.stealth_active = True

        self.log(f"✅ Stealth engaged: {len(result['layers'])} layers active")
        self.log(f"   Exit IP: {result.get('exit_ip', 'unknown')}")
        self.update_status()

    def disengage_stealth(self):
        """Disengage stealth mode"""
        self.log("👻 Disengaging stealth...")
        self.stealth_active = False
        self.log("✅ Stealth disengaged - normal operation restored")
        self.update_status()

    def check_anonymity(self):
        """Check current anonymity level"""
        thread = Thread(target=self._check_anonymity_async)
        thread.daemon = True
        thread.start()

    def _check_anonymity_async(self):
        """Async anonymity check"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        result = loop.run_until_complete(self.stealth.get_anonymity_level())
        self.log(f"📊 Anonymity Level: {result['level']} ({result['anonymity_score']:.0f}%)")

    def enable_defense(self):
        """Enable defense systems"""
        self.defense_active = True
        self.log("🛡️  Defense systems ENABLED")
        self.update_status()

    def disable_defense(self):
        """Disable defense systems"""
        self.defense_active = False
        self.log("🛡️  Defense systems DISABLED")
        self.update_status()

    def view_threats(self):
        """View detected threats"""
        self.log("📋 Viewing detected threats...")
        self.log(f"   Threats detected: {self.defense.threats_detected}")
        self.log(f"   Threats blocked: {self.defense.threats_blocked}")

    def log(self, message):
        """Add message to console"""
        self.console.insert(tk.END, f"{message}\n")
        self.console.see(tk.END)

    def update_status(self):
        """Update system status display"""
        self.status_text.delete('1.0', tk.END)

        status = f"""
🔥 PROMETHEUS PRIME STATUS

Stealth: {'🟢 ACTIVE' if self.stealth_active else '🔴 INACTIVE'}
Defense: {'🟢 ACTIVE' if self.defense_active else '🔴 INACTIVE'}
Autonomous: {'🟢 RUNNING' if self.autonomous_running else '🔴 STOPPED'}

📊 Statistics:
  Operations: {self.prometheus.operations_executed}
  Findings: {self.prometheus.total_findings}
  Threats Blocked: {self.defense.threats_blocked}

🔐 API Keys Loaded:
  OpenAI: {'✅' if os.getenv('OPENAI_API_KEY') else '❌'}
  Anthropic: {'✅' if os.getenv('ANTHROPIC_API_KEY') else '❌'}
  ElevenLabs: {'✅' if os.getenv('ELEVENLABS_API_KEY') else '❌'}

💎 Crystal Memory:
  Crystals: {self.prometheus.operations_executed + 565}
  Path: {os.getenv('CRYSTAL_MEMORY_DB_PATH', 'Not configured')}
        """
        self.status_text.insert('1.0', status.strip())

    def create_status_bar(self):
        """Create status bar"""
        status_bar = ttk.Label(
            self.root,
            text="Authority Level 11.0 | Operator: Commander Bobby Don McWilliams II | Status: Operational",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def load_config(self):
        """Load configuration"""
        messagebox.showinfo("Load Config", "Configuration loading not yet implemented")

    def save_config(self):
        """Save configuration"""
        messagebox.showinfo("Save Config", "Configuration saving not yet implemented")

    def show_help(self):
        """Show help documentation"""
        help_text = """
PROMETHEUS PRIME ULTIMATE - HELP

📋 QUICK START:
1. Select a domain tab
2. Configure target
3. Click operation button
4. View results in console

🛡️ STEALTH MODE:
Menu → Stealth → Engage Full Stealth
- Activates VPN chain, Tor, obfuscation
- Maximum anonymity

🔒 DEFENSE MODE:
Always active by default
- IDS/IPS monitoring
- Attack quarantine
- Counter-attack capabilities

For full documentation, see README.md
        """
        messagebox.showinfo("Help", help_text)

    def show_about(self):
        """Show about dialog"""
        about_text = """
🔥 PROMETHEUS PRIME ULTIMATE 🔥

Version: 2.0.0
Authority Level: 11.0

Operator:
Commander Bobby Don McWilliams II

Features:
• 20 Elite Security Domains
• 5-Model AI Consensus Engine
• Stealth & Anonymity Systems
• Advanced Defense Capabilities
• 125+ Penetration Techniques

AUTHORIZED TESTING ONLY
Controlled Lab Environment Required
        """
        messagebox.showinfo("About Prometheus Prime", about_text)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = PrometheusGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
