#!/usr/bin/env python3
"""
🎯 PROMETHEUS PRIME - UNIFIED OSINT API SERVER
Combines Phone Intelligence + Social OSINT into one REST API
Authority Level: 11.0
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime

# Load master API keychain FIRST (highest priority)
master_keychain = Path(r"P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env")
if master_keychain.exists():
    load_dotenv(master_keychain)
    print(f"✅ Master API Keychain loaded: {master_keychain}")
else:
    print(f"⚠️ Master keychain not found: {master_keychain}")

# Add module paths
sys.path.append(str(Path(__file__).parent))

from phone_intelligence import PhoneIntelligence
from social_osint import SocialOSINT
from domain_intelligence import DomainIntelligence
from email_intelligence import EmailIntelligence
from ip_intelligence import IPIntelligence

app = Flask(__name__)
CORS(app)  # Enable CORS for GUI

# Initialize modules
print("🔧 Initializing OSINT modules...")
print(f"   Twilio SID: {os.getenv('TWILIO_ACCOUNT_SID', 'NOT FOUND')[:10]}...")
print(f"   Reddit Client ID: {os.getenv('REDDIT_CLIENT_ID', 'NOT FOUND')[:10]}...")
print(f"   WhoisXML API: {os.getenv('WHOISXML_API_KEY', 'NOT FOUND')[:10]}...")
print(f"   HIBP API: {os.getenv('HIBP_API_KEY', 'NOT FOUND')[:10]}...")
print(f"   Shodan API: {os.getenv('SHODAN_API_KEY', 'NOT FOUND')[:10]}...")
phone_intel = PhoneIntelligence()
social_osint = SocialOSINT()
domain_intel = DomainIntelligence()
email_intel = EmailIntelligence()
ip_intel = IPIntelligence()
print("✅ OSINT API Server ready (5 modules)")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'modules': {
            'phone_intelligence': True,
            'social_osint': True,
            'domain_intelligence': True,
            'email_intelligence': True,
            'ip_intelligence': True
        }
    })

@app.route('/api/keys/status', methods=['GET'])
def keys_status():
    """Check which API keys are loaded"""
    keys_status = {
        'twilio': bool(os.getenv('TWILIO_ACCOUNT_SID')),
        'reddit': bool(os.getenv('REDDIT_CLIENT_ID')),
        'google': bool(os.getenv('GOOGLE_API_KEY')),
        'elevenlabs': bool(os.getenv('ELEVENLABS_API_KEY')),
        'openai': bool(os.getenv('OPENAI_API_KEY')),
        'anthropic': bool(os.getenv('ANTHROPIC_API_KEY')),
        'numverify': bool(os.getenv('NUMVERIFY_API_KEY')),
        'whoisxml': bool(os.getenv('WHOISXML_API_KEY')),
        'hibp': bool(os.getenv('HIBP_API_KEY')),
        'virustotal': bool(os.getenv('VIRUSTOTAL_API_KEY'))
    }
    
    return jsonify({
        'status': 'online',
        'keychain_loaded': True,
        'keys': keys_status,
        'keys_loaded': sum(keys_status.values()),
        'total_keys': len(keys_status)
    })

@app.route('/api/phone/lookup', methods=['POST'])
def phone_lookup():
    """
    Reverse phone lookup with caller name
    Request: {"phone": "+15555551234"}
    """
    try:
        data = request.get_json()
        phone = data.get('phone')
        
        if not phone:
            return jsonify({'error': 'Phone number required'}), 400
        
        # Get caller name from Twilio
        result = phone_intel.lookup(phone)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/social/search', methods=['POST'])
def social_search():
    """
    Social OSINT search
    Request: {"name": "John Doe", "phone": "+15555551234", "location": "Texas"}
    """
    try:
        data = request.get_json()
        name = data.get('name')
        phone = data.get('phone')
        location = data.get('location')
        
        if not name:
            return jsonify({'error': 'Name required'}), 400
        
        # Perform social OSINT search
        result = social_osint.full_osint_report(name, phone, location)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/domain/lookup', methods=['POST'])
def domain_lookup():
    """
    Domain intelligence lookup (WHOIS, DNS, reputation)
    Request: {"domain": "example.com"}
    """
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        
        # Perform domain lookup
        result = domain_intel.lookup(domain)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/domain/batch', methods=['POST'])
def domain_batch():
    """
    Batch domain lookup
    Request: {"domains": ["example.com", "test.com"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        
        if not domains or not isinstance(domains, list):
            return jsonify({'error': 'Domains array required'}), 400
        
        # Perform batch lookup
        results = domain_intel.batch_lookup(domains)
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/analyze', methods=['POST'])
def email_analyze():
    """
    Email intelligence analysis (breach check, validation, reputation)
    Request: {"email": "test@example.com"}
    """
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email required'}), 400
        
        # Perform email analysis
        result = email_intel.analyze(email)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/batch', methods=['POST'])
def email_batch():
    """
    Batch email analysis
    Request: {"emails": ["test@example.com", "user@test.com"]}
    """
    try:
        data = request.get_json()
        emails = data.get('emails', [])
        
        if not emails or not isinstance(emails, list):
            return jsonify({'error': 'Emails array required'}), 400
        
        # Perform batch analysis
        results = email_intel.batch_analyze(emails)
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/password/breach', methods=['POST'])
def password_breach():
    """
    Check if password has been compromised (k-anonymity)
    Request: {"password": "mypassword123"}
    """
    try:
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({'error': 'Password required'}), 400
        
        # Check password breach
        result = email_intel.check_password_breach(password)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip/analyze', methods=['POST'])
def ip_analyze():
    """
    IP intelligence analysis (geolocation, reputation, abuse reports, Shodan)
    Request: {"ip": "8.8.8.8"}
    """
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        # Perform IP analysis
        result = ip_intel.analyze(ip)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip/batch', methods=['POST'])
def ip_batch():
    """
    Batch IP analysis
    Request: {"ips": ["8.8.8.8", "1.1.1.1"]}
    """
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        
        if not ips or not isinstance(ips, list):
            return jsonify({'error': 'IPs array required'}), 400
        
        # Perform batch analysis
        results = ip_intel.batch_analyze(ips)
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/osint/full', methods=['POST'])
def full_osint():
    """
    Complete OSINT report combining phone + social + domain + email
    Request: {"name": "John Doe", "phone": "+15555551234", "email": "test@example.com", "domain": "example.com", "location": "Texas"}
    """
    try:
        data = request.get_json()
        name = data.get('name')
        phone = data.get('phone')
        email = data.get('email')
        domain = data.get('domain')
        location = data.get('location')
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'apis_available': {}
        }
        
        # Check which APIs are available
        results['apis_available'] = {
            'twilio': bool(os.getenv('TWILIO_ACCOUNT_SID')),
            'reddit': bool(os.getenv('REDDIT_CLIENT_ID')),
            'numverify': bool(os.getenv('NUMVERIFY_API_KEY')),
            'whoisxml': bool(os.getenv('WHOISXML_API_KEY')),
            'hibp': bool(os.getenv('HIBP_API_KEY')),
            'virustotal': bool(os.getenv('VIRUSTOTAL_API_KEY'))
        }
        
        # Phone lookup if provided
        if phone:
            results['phone_intel'] = phone_intel.lookup(phone)
            
            # Add NumVerify validation if available
            if os.getenv('NUMVERIFY_API_KEY'):
                results['phone_intel']['numverify_available'] = True
        
        # Social OSINT if name provided
        if name:
            results['social_osint'] = social_osint.full_osint_report(name, phone, location)
        
        # Domain intelligence if provided
        if domain:
            results['domain_intel'] = domain_intel.lookup(domain)
        
        # Email intelligence if provided
        if email:
            results['email_intel'] = email_intel.analyze(email)
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("="*60)
    print("🎯 PROMETHEUS PRIME - UNIFIED OSINT API")
    print("   Port: 8343")
    print("   Authority Level: 11.0")
    print("\n   📡 Endpoints (13 total):")
    print("   • GET  /api/health")
    print("   • GET  /api/keys/status")
    print("   • POST /api/phone/lookup")
    print("   • POST /api/social/search")
    print("   • POST /api/domain/lookup")
    print("   • POST /api/domain/batch")
    print("   • POST /api/email/analyze")
    print("   • POST /api/email/batch")
    print("   • POST /api/password/breach")
    print("   • POST /api/ip/analyze")
    print("   • POST /api/ip/batch")
    print("   • POST /api/osint/full")
    print("\n   🔑 APIs Loaded:")
    print(f"   • Twilio: {bool(os.getenv('TWILIO_ACCOUNT_SID'))}")
    print(f"   • Reddit: {bool(os.getenv('REDDIT_CLIENT_ID'))}")
    print(f"   • WhoisXML: {bool(os.getenv('WHOISXML_API_KEY'))}")
    print(f"   • VirusTotal: {bool(os.getenv('VIRUSTOTAL_API_KEY'))}")
    print(f"   • HIBP: {bool(os.getenv('HIBP_API_KEY'))}")
    print(f"   • Hunter.io: {bool(os.getenv('HUNTER_IO_API_KEY'))}")
    print(f"   • Shodan: {bool(os.getenv('SHODAN_API_KEY'))}")
    print(f"   • AbuseIPDB: {bool(os.getenv('ABUSEIPDB_API_KEY'))}")
    print("\n   🔥 Phoenix Healing: ENABLED")
    print("   📊 Modules: 5 (Phone, Social, Domain, Email, IP)")
    print("="*60)
    
    app.run(host='0.0.0.0', port=8343, debug=False)
