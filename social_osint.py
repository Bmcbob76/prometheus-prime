#!/usr/bin/env python3
"""
🎯 PROMETHEUS PRIME - SOCIAL OSINT MODULE
Multi-source people search using existing APIs
Authority Level: 11.0
"""

import os
import json
import requests
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

class SocialOSINT:
    def __init__(self):
        print("🔧 Initializing Social OSINT Module...", flush=True)
        
        # Load credentials from local .env first, then fallback to master keychain
        local_env = Path(__file__).parent / ".env"
        if local_env.exists():
            print(f"📁 Loading credentials from: {local_env}", flush=True)
            load_dotenv(local_env)
        else:
            print(f"📁 Loading credentials from: P:\\ECHO_PRIME\\CONFIG\\echo_x_complete_api_keychain.env", flush=True)
            load_dotenv(r"P:\ECHO_PRIME\CONFIG\echo_x_complete_api_keychain.env")
        
        # Reddit credentials
        self.reddit_client_id = os.getenv('REDDIT_CLIENT_ID')
        self.reddit_secret = os.getenv('REDDIT_CLIENT_SECRET')
        self.reddit_username = os.getenv('REDDIT_USERNAME')
        self.reddit_password = os.getenv('REDDIT_PASSWORD')
        
        # Get Reddit OAuth token
        self.reddit_token = self._get_reddit_token()
        
        print("✅ Social OSINT Module initialized", flush=True)
        if self.reddit_token:
            print(f"   Reddit API: ✅ Authenticated", flush=True)
        else:
            print(f"   Reddit API: ⚠️ Skipped (auth failed, will continue without)", flush=True)
    
    def _get_reddit_token(self):
        """Get Reddit OAuth token"""
        try:
            # Check if credentials exist before attempting auth
            if not all([self.reddit_client_id, self.reddit_secret, self.reddit_username, self.reddit_password]):
                print("⚠️ Reddit credentials missing - skipping Reddit search", flush=True)
                print(f"   Client ID: {'✅' if self.reddit_client_id else '❌'}", flush=True)
                print(f"   Secret: {'✅' if self.reddit_secret else '❌'}", flush=True)
                print(f"   Username: {'✅' if self.reddit_username else '❌'}", flush=True)
                print(f"   Password: {'✅' if self.reddit_password else '❌'}", flush=True)
                return None
                
            print("🔑 Attempting Reddit authentication...", flush=True)
            auth = requests.auth.HTTPBasicAuth(self.reddit_client_id, self.reddit_secret)
            data = {
                'grant_type': 'password',
                'username': self.reddit_username,
                'password': self.reddit_password
            }
            headers = {'User-Agent': 'EchoPrimeHarvester/1.0'}
            
            response = requests.post('https://www.reddit.com/api/v1/access_token',
                                    auth=auth, data=data, headers=headers)
            
            if response.status_code == 200:
                json_resp = response.json()
                if 'access_token' in json_resp:
                    print("✅ Reddit authentication successful!")
                    return json_resp['access_token']
                else:
                    print(f"⚠️ Reddit auth response missing token: {json_resp}")
                    return None
            else:
                print(f"⚠️ Reddit auth failed ({response.status_code}): {response.text[:200]}")
                return None
        except Exception as e:
            print(f"⚠️ Reddit auth error: {e}")
            return None
    
    def search_reddit(self, query, limit=25):
        """Search Reddit for mentions of person/phone"""
        if not self.reddit_token:
            return {'error': 'Reddit authentication failed'}
        
        headers = {
            'Authorization': f'bearer {self.reddit_token}',
            'User-Agent': 'EchoPrimeHarvester/1.0'
        }
        
        params = {
            'q': query,
            'limit': limit,
            'sort': 'relevance'
        }
        
        response = requests.get('https://oauth.reddit.com/search',
                              headers=headers, params=params)
        
        if response.status_code != 200:
            return {'error': f'Reddit API error: {response.status_code}'}
        
        data = response.json()
        results = []
        
        for post in data['data']['children']:
            post_data = post['data']
            results.append({
                'title': post_data['title'],
                'author': post_data['author'],
                'subreddit': post_data['subreddit'],
                'url': f"https://reddit.com{post_data['permalink']}",
                'score': post_data['score'],
                'created': datetime.fromtimestamp(post_data['created_utc']).isoformat(),
                'text': post_data.get('selftext', '')[:200]
            })
        
        return results
    
    def google_dork_builder(self, name, phone=None, location=None):
        """Build Google search queries for OSINT"""
        queries = []
        
        # Basic name search
        queries.append(f'"{name}"')
        
        # Name + location
        if location:
            queries.append(f'"{name}" "{location}"')
            queries.append(f'"{name}" {location} site:linkedin.com')
            queries.append(f'"{name}" {location} site:facebook.com')
        
        # Name + phone
        if phone:
            # Remove formatting
            clean_phone = phone.replace('+1', '').replace('-', '').replace(' ', '').replace('(', '').replace(')', '')
            queries.append(f'"{name}" {clean_phone}')
            queries.append(f'{clean_phone}')
        
        # Social media specific
        queries.append(f'"{name}" site:linkedin.com')
        queries.append(f'"{name}" site:facebook.com')
        queries.append(f'"{name}" site:instagram.com')
        queries.append(f'"{name}" site:twitter.com')
        
        # Public records
        if location:
            queries.append(f'"{name}" {location} "public records"')
            queries.append(f'"{name}" {location} "arrest records"')
        
        return queries
    
    def generate_search_links(self, name, phone=None, location=None):
        """Generate direct search URLs"""
        import urllib.parse
        
        links = {}
        
        # Google
        google_query = f'"{name}"'
        if phone:
            google_query += f' {phone}'
        if location:
            google_query += f' {location}'
        links['google'] = f"https://www.google.com/search?q={urllib.parse.quote(google_query)}"
        
        # LinkedIn
        links['linkedin'] = f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(name)}"
        
        # Facebook
        links['facebook'] = f"https://www.facebook.com/search/people/?q={urllib.parse.quote(name)}"
        
        # Instagram
        links['instagram'] = f"https://www.instagram.com/explore/tags/{urllib.parse.quote(name.replace(' ', ''))}"
        
        # Twitter/X
        links['twitter'] = f"https://twitter.com/search?q={urllib.parse.quote(name)}"
        
        # Spokeo (manual)
        links['spokeo'] = f"https://www.spokeo.com/{urllib.parse.quote(name.replace(' ', '-'))}"
        
        # TrueCaller (manual)
        if phone:
            clean_phone = phone.replace('+', '').replace('-', '').replace(' ', '')
            links['truecaller'] = f"https://www.truecaller.com/search/{clean_phone}"
        
        return links
    
    def full_osint_report(self, name, phone=None, location=None):
        """Generate comprehensive OSINT report"""
        print("="*60)
        print(f"🎯 SOCIAL OSINT REPORT: {name}")
        if phone:
            print(f"📞 Phone: {phone}")
        if location:
            print(f"📍 Location: {location}")
        print("="*60)
        
        report = {
            'target': name,
            'phone': phone,
            'location': location,
            'timestamp': datetime.now().isoformat(),
            'results': {}
        }
        
        # Reddit search
        if self.reddit_token:
            print("\n🔍 Searching Reddit...")
            reddit_query = name
            if location:
                reddit_query += f" {location}"
            reddit_results = self.search_reddit(reddit_query)
            report['results']['reddit'] = reddit_results
            
            if isinstance(reddit_results, list):
                print(f"   Found {len(reddit_results)} Reddit mentions")
                for r in reddit_results[:3]:
                    print(f"   • r/{r['subreddit']}: {r['title'][:60]}...")
        else:
            print("\n⚠️ Skipping Reddit search (no auth token)")
            report['results']['reddit'] = []
        
        # Generate search links
        print("\n🌐 Generated search links:")
        links = self.generate_search_links(name, phone, location)
        report['search_links'] = links
        
        for platform, url in links.items():
            print(f"   • {platform.title()}: {url}")
        
        # Google dork queries
        print("\n🔎 Google dork queries:")
        dorks = self.google_dork_builder(name, phone, location)
        report['google_dorks'] = dorks
        
        for i, dork in enumerate(dorks[:5], 1):
            print(f"   {i}. {dork}")
        
        # Save report
        report_path = Path(r"P:\ECHO_PRIME\OSINT_REPORTS")
        report_path.mkdir(exist_ok=True)
        
        filename = f"osint_{name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file = report_path / filename
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Report saved: {report_file}")
        
        return report


def main():
    """CLI interface"""
    import sys
    
    print("="*60, flush=True)
    print("🎯 PROMETHEUS PRIME - SOCIAL OSINT", flush=True)
    print("   Multi-source people search", flush=True)
    print("   Authority Level: 11.0", flush=True)
    print("="*60, flush=True)
    
    try:
        osint = SocialOSINT()
    except Exception as e:
        print(f"❌ ERROR initializing Social OSINT: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return
    
    # Interactive mode
    print("\n📝 Target Information")
    name = input("Name: ").strip()
    phone = input("Phone (optional): ").strip() or None
    location = input("Location (optional): ").strip() or None
    
    if not name:
        print("❌ Name required")
        return
    
    # Generate report
    osint.full_osint_report(name, phone, location)
    
    print("\n✅ OSINT search complete!")
    print("   Open links above to manually search social media")
    print("   Use Google dorks for advanced searching")


if __name__ == "__main__":
    main()
