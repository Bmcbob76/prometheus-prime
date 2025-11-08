#!/usr/bin/env python3
"""
🎯 PROMETHEUS PRIME - PHONE INTELLIGENCE MODULE
Twilio Caller Name (CNAM) Lookup with Smart Caching
Authority Level: 11.0
"""

import os
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from twilio.rest import Client
from dotenv import load_dotenv

class PhoneIntelligence:
    def __init__(self):
        # Load credentials
        load_dotenv(r"P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env")
        
        self.twilio_sid = os.getenv('TWILIO_ACCOUNT_SID')
        self.twilio_token = os.getenv('TWILIO_AUTH_TOKEN')
        
        if not self.twilio_sid or not self.twilio_token:
            raise ValueError("❌ Twilio credentials not found in keychain")
        
        # Initialize Twilio client
        self.client = Client(self.twilio_sid, self.twilio_token)
        
        # Cache database
        self.cache_db = Path(r"P:\ECHO_PRIME\DATABASES\phone_intel_cache.db")
        self.cache_db.parent.mkdir(parents=True, exist_ok=True)
        self._init_cache_db()
        
        # Cache settings
        self.cache_ttl_days = 30  # Cache caller names for 30 days
        
        print("✅ Phone Intelligence Module initialized")
        print(f"   Twilio Account: {self.twilio_sid[:10]}...")
        print(f"   Cache: {self.cache_db}")
    
    def _init_cache_db(self):
        """Initialize cache database"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phone_lookups (
                phone_number TEXT PRIMARY KEY,
                caller_name TEXT,
                caller_type TEXT,
                carrier_name TEXT,
                carrier_type TEXT,
                country_code TEXT,
                national_format TEXT,
                lookup_date TIMESTAMP,
                last_updated TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_lookup_date 
            ON phone_lookups(lookup_date)
        """)
        
        conn.commit()
        conn.close()
    
    def _check_cache(self, phone_number):
        """Check if phone number is in cache and still valid"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM phone_lookups 
            WHERE phone_number = ?
        """, (phone_number,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        # Check if cache is still valid
        lookup_date = datetime.fromisoformat(result[7])
        if datetime.now() - lookup_date > timedelta(days=self.cache_ttl_days):
            return None  # Cache expired
        
        return {
            'phone_number': result[0],
            'caller_name': result[1],
            'caller_type': result[2],
            'carrier_name': result[3],
            'carrier_type': result[4],
            'country_code': result[5],
            'national_format': result[6],
            'lookup_date': result[7],
            'cached': True
        }
    
    def _save_to_cache(self, phone_data):
        """Save lookup result to cache"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO phone_lookups 
            (phone_number, caller_name, caller_type, carrier_name, carrier_type,
             country_code, national_format, lookup_date, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            phone_data['phone_number'],
            phone_data.get('caller_name'),
            phone_data.get('caller_type'),
            phone_data.get('carrier_name'),
            phone_data.get('carrier_type'),
            phone_data.get('country_code'),
            phone_data.get('national_format'),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def lookup(self, phone_number, use_cache=True):
        """
        Lookup phone number and get caller name
        
        Args:
            phone_number: Phone number in E.164 format (+1XXXXXXXXXX)
            use_cache: Use cached results if available
        
        Returns:
            dict: Phone intelligence data
        """
        # Normalize phone number
        if not phone_number.startswith('+'):
            phone_number = '+1' + phone_number.replace('-', '').replace(' ', '')
        
        print(f"\n🔍 Looking up: {phone_number}")
        
        # Check cache first
        if use_cache:
            cached = self._check_cache(phone_number)
            if cached:
                print(f"✅ Found in cache (age: {(datetime.now() - datetime.fromisoformat(cached['lookup_date'])).days} days)")
                return cached
        
        # Perform Twilio lookup
        try:
            print("📞 Querying Twilio Lookup API...")
            
            phone_info = self.client.lookups.v2.phone_numbers(phone_number).fetch(
                fields='caller_name,line_type_intelligence'
            )
            
            # Extract data
            result = {
                'phone_number': phone_number,
                'caller_name': phone_info.caller_name.get('caller_name') if phone_info.caller_name else 'Unknown',
                'caller_type': phone_info.caller_name.get('caller_type') if phone_info.caller_name else 'Unknown',
                'carrier_name': phone_info.line_type_intelligence.get('carrier_name') if phone_info.line_type_intelligence else None,
                'carrier_type': phone_info.line_type_intelligence.get('type') if phone_info.line_type_intelligence else None,
                'country_code': phone_info.country_code,
                'national_format': phone_info.national_format,
                'cached': False
            }
            
            # Save to cache
            self._save_to_cache(result)
            
            print(f"✅ Lookup complete:")
            print(f"   Caller: {result['caller_name']}")
            print(f"   Type: {result['caller_type']}")
            print(f"   Carrier: {result['carrier_name']}")
            
            return result
            
        except Exception as e:
            print(f"❌ Lookup failed: {e}")
            return {
                'phone_number': phone_number,
                'error': str(e),
                'cached': False
            }
    
    def bulk_lookup(self, phone_numbers, use_cache=True):
        """
        Lookup multiple phone numbers
        
        Args:
            phone_numbers: List of phone numbers
            use_cache: Use cached results if available
        
        Returns:
            dict: Results keyed by phone number
        """
        results = {}
        
        print(f"\n🔍 Bulk lookup: {len(phone_numbers)} numbers")
        
        for i, phone in enumerate(phone_numbers, 1):
            print(f"\n[{i}/{len(phone_numbers)}]", end=" ")
            results[phone] = self.lookup(phone, use_cache=use_cache)
        
        return results
    
    def get_cache_stats(self):
        """Get cache statistics"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM phone_lookups")
        total = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM phone_lookups 
            WHERE lookup_date > ?
        """, ((datetime.now() - timedelta(days=self.cache_ttl_days)).isoformat(),))
        valid = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_cached': total,
            'valid_cache': valid,
            'expired': total - valid,
            'cache_ttl_days': self.cache_ttl_days
        }
    
    def clear_expired_cache(self):
        """Remove expired cache entries"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cutoff = (datetime.now() - timedelta(days=self.cache_ttl_days)).isoformat()
        
        cursor.execute("DELETE FROM phone_lookups WHERE lookup_date < ?", (cutoff,))
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"✅ Cleared {deleted} expired cache entries")
        return deleted


# ==================== CLI INTERFACE ====================

def main():
    """CLI interface for phone intelligence"""
    import sys
    
    print("="*60)
    print("🎯 PROMETHEUS PRIME - PHONE INTELLIGENCE")
    print("   Twilio CNAM + Smart Caching")
    print("   Authority Level: 11.0")
    print("="*60)
    
    # Initialize
    intel = PhoneIntelligence()
    
    # Check cache stats
    stats = intel.get_cache_stats()
    print(f"\n📊 Cache Status:")
    print(f"   Total cached: {stats['total_cached']}")
    print(f"   Valid: {stats['valid_cache']}")
    print(f"   Expired: {stats['expired']}")
    
    if len(sys.argv) > 1:
        # Command line phone number
        phone = sys.argv[1]
        result = intel.lookup(phone)
        
        if 'error' not in result:
            print(f"\n" + "="*60)
            print(f"📞 {result['national_format']}")
            print(f"👤 {result['caller_name']}")
            print(f"🏢 {result['caller_type']}")
            print(f"📡 {result['carrier_name']} ({result['carrier_type']})")
            print("="*60)
    else:
        # Interactive mode
        print("\n🎯 Interactive Mode")
        print("Enter phone numbers (Ctrl+C to exit)")
        
        while True:
            try:
                phone = input("\n📞 Phone number: ").strip()
                
                if not phone:
                    continue
                
                result = intel.lookup(phone)
                
                if 'error' in result:
                    print(f"❌ Error: {result['error']}")
                else:
                    print(f"\n" + "-"*40)
                    print(f"📞 {result['national_format']}")
                    print(f"👤 {result['caller_name']}")
                    print(f"🏢 {result['caller_type']}")
                    print(f"📡 {result['carrier_name']} ({result['carrier_type']})")
                    if result['cached']:
                        print(f"💾 From cache")
                    print("-"*40)
                    
            except KeyboardInterrupt:
                print("\n\n👋 Exiting...")
                break
            except Exception as e:
                print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
