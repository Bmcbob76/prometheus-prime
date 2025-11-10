#!/usr/bin/env python3
"""
🔍 SOCIAL MEDIA OSINT MODULE
Social media intelligence gathering, username enumeration, profile discovery
Authority Level: 11.0

⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️
"""

import requests
import json
from typing import Dict, Any, List
from datetime import datetime
import re

class SocialOSINT:
    """Social media OSINT and username enumeration"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        print("🔍 Social OSINT Module initialized")

    def username_search(self, username: str) -> Dict[str, Any]:
        """
        Search for username across multiple platforms

        Args:
            username: Username to search for
        """
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Medium': f'https://medium.com/@{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'Discord': f'https://discord.com/users/{username}',
            'Telegram': f'https://t.me/{username}',
            'Snapchat': f'https://snapchat.com/add/{username}'
        }

        found = []
        not_found = []

        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=5, allow_redirects=True)

                if response.status_code == 200:
                    found.append({
                        'platform': platform,
                        'url': url,
                        'status': response.status_code,
                        'exists': True
                    })
                else:
                    not_found.append({
                        'platform': platform,
                        'url': url,
                        'status': response.status_code,
                        'exists': False
                    })
            except:
                not_found.append({
                    'platform': platform,
                    'url': url,
                    'exists': False,
                    'error': 'Timeout or connection error'
                })

        return {
            'username': username,
            'found': found,
            'not_found': not_found,
            'total_found': len(found),
            'total_searched': len(platforms),
            'timestamp': datetime.now().isoformat()
        }

    def reddit_profile(self, username: str) -> Dict[str, Any]:
        """Get Reddit user profile information"""
        try:
            url = f'https://www.reddit.com/user/{username}/about.json'
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                user_data = data.get('data', {})

                return {
                    'username': username,
                    'profile': {
                        'name': user_data.get('name'),
                        'created_utc': user_data.get('created_utc'),
                        'link_karma': user_data.get('link_karma'),
                        'comment_karma': user_data.get('comment_karma'),
                        'is_gold': user_data.get('is_gold'),
                        'is_mod': user_data.get('is_mod'),
                        'has_verified_email': user_data.get('has_verified_email')
                    },
                    'exists': True,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {'username': username, 'exists': False, 'error': 'User not found'}

        except Exception as e:
            return {'username': username, 'error': str(e)}

    def github_profile(self, username: str) -> Dict[str, Any]:
        """Get GitHub user profile information"""
        try:
            url = f'https://api.github.com/users/{username}'
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()

                return {
                    'username': username,
                    'profile': {
                        'name': data.get('name'),
                        'company': data.get('company'),
                        'blog': data.get('blog'),
                        'location': data.get('location'),
                        'email': data.get('email'),
                        'bio': data.get('bio'),
                        'public_repos': data.get('public_repos'),
                        'public_gists': data.get('public_gists'),
                        'followers': data.get('followers'),
                        'following': data.get('following'),
                        'created_at': data.get('created_at'),
                        'updated_at': data.get('updated_at')
                    },
                    'exists': True,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {'username': username, 'exists': False, 'error': 'User not found'}

        except Exception as e:
            return {'username': username, 'error': str(e)}

    def email_to_username(self, email: str) -> List[str]:
        """Extract potential usernames from email"""
        # Extract local part
        if '@' not in email:
            return []

        local_part = email.split('@')[0]
        usernames = [local_part]

        # Generate variations
        if '.' in local_part:
            parts = local_part.split('.')
            usernames.append(''.join(parts))  # Remove dots
            usernames.append('_'.join(parts))  # Replace with underscores

        if '_' in local_part:
            usernames.append(local_part.replace('_', ''))
            usernames.append(local_part.replace('_', '.'))

        # Remove duplicates
        return list(set(usernames))

    def phone_to_social(self, phone: str) -> Dict[str, Any]:
        """Search for social profiles by phone number"""
        # This would typically use phone reverse lookup APIs
        # Placeholder for authorized use

        return {
            'phone': phone,
            'method': 'Phone reverse lookup',
            'platforms': [],
            'note': 'Requires API integration for live data',
            'timestamp': datetime.now().isoformat()
        }

    def full_osint_report(self, name: str, phone: str = None, location: str = None) -> Dict[str, Any]:
        """Generate comprehensive OSINT report"""
        report = {
            'target': {
                'name': name,
                'phone': phone,
                'location': location
            },
            'timestamp': datetime.now().isoformat(),
            'findings': {}
        }

        # Generate username variations from name
        username_variations = self._generate_username_variations(name)

        # Search each variation
        all_found = []
        for username in username_variations[:5]:  # Limit to top 5 variations
            result = self.username_search(username)
            if result['total_found'] > 0:
                all_found.extend(result['found'])

        report['findings']['username_search'] = {
            'variations_tested': username_variations[:5],
            'profiles_found': all_found,
            'total_found': len(all_found)
        }

        # Phone search if provided
        if phone:
            report['findings']['phone_search'] = self.phone_to_social(phone)

        return report

    def _generate_username_variations(self, name: str) -> List[str]:
        """Generate common username variations from name"""
        name = name.lower().strip()
        parts = name.split()

        variations = [
            name.replace(' ', ''),
            name.replace(' ', '_'),
            name.replace(' ', '.'),
            name.replace(' ', '-')
        ]

        if len(parts) >= 2:
            # First + Last
            variations.append(parts[0] + parts[-1])
            variations.append(parts[0] + '_' + parts[-1])
            variations.append(parts[0] + '.' + parts[-1])

            # First initial + Last
            variations.append(parts[0][0] + parts[-1])
            variations.append(parts[0][0] + '_' + parts[-1])

            # Last + First initial
            variations.append(parts[-1] + parts[0][0])

        # Remove duplicates and empty
        variations = list(set([v for v in variations if v]))

        return variations

    def search_by_location(self, location: str, platform: str = 'all') -> Dict[str, Any]:
        """Search for profiles by location"""
        return {
            'location': location,
            'platform': platform,
            'method': 'Location-based search',
            'note': 'Requires platform-specific API integration',
            'timestamp': datetime.now().isoformat()
        }


if __name__ == '__main__':
    so = SocialOSINT()

    # Test
    username = input("Enter username to search: ").strip()
    if username:
        result = so.username_search(username)
        print(json.dumps(result, indent=2))
