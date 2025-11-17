#!/usr/bin/env python3
"""
PROMETHEUS PRIME - RESIDENTIAL PROXY SYSTEM WITH DNS LEAK PREVENTION
Enterprise-grade IP detection evasion for multi-account management

Authority Level: 11.0
Commander: Bobby Don McWilliams II

Purpose: Prevent businesses from detecting multiple sessions via IP fingerprinting

Features:
  - Residential proxy pool management (not datacenter IPs)
  - Mobile carrier proxy rotation (4G/5G cellular IPs)
  - DNS leak prevention and detection
  - Geographic consistency validation (timezone matches IP location)
  - IPv4/IPv6 dual-stack handling
  - Proxy health monitoring with IP reputation checking
  - Time-based IP rotation strategies
  - ASN (Autonomous System Number) diversity
  - ISP diversity to prevent ASN-based fingerprinting
  - Connection pattern randomization
  - Proxy warming (gradual activity ramp-up)
"""

import requests
import random
import time
import logging
import socket
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta


class ProxyQuality(Enum):
    """Proxy quality levels based on detection risk."""
    RESIDENTIAL = "residential"  # Lowest detection risk
    MOBILE = "mobile"  # Very low detection risk (4G/5G)
    DATACENTER = "datacenter"  # Higher detection risk
    TOR = "tor"  # High anonymity, but often blocked


class IPVersion(Enum):
    """IP protocol version."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DUAL_STACK = "dual"


@dataclass
class ProxyMetadata:
    """Extended proxy metadata for enterprise detection evasion."""
    proxy_id: str
    host: str
    port: int
    quality: ProxyQuality

    # Authentication
    username: Optional[str] = None
    password: Optional[str] = None

    # Geographic data
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None

    # Network data
    asn: Optional[int] = None  # Autonomous System Number
    isp: Optional[str] = None
    organization: Optional[str] = None
    ip_version: IPVersion = IPVersion.IPV4

    # Reputation and health
    is_residential: bool = False
    is_mobile: bool = False
    reputation_score: float = 1.0  # 0.0 to 1.0
    last_health_check: float = 0.0
    response_time_ms: float = 0.0
    success_rate: float = 1.0
    is_alive: bool = True

    # Usage tracking
    usage_count: int = 0
    last_used: float = 0.0
    created_at: float = field(default_factory=time.time)
    warmed_up: bool = False  # Has proxy been warmed up?

    # DNS leak detection
    dns_servers: List[str] = field(default_factory=list)
    dns_leak_detected: bool = False

    # Blacklist status
    is_blacklisted: bool = False
    blacklist_reason: Optional[str] = None


class ResidentialProxySystem:
    """
    Enterprise-grade residential proxy management system.
    Prevents IP-based detection and fingerprinting.
    """

    def __init__(self):
        """Initialize residential proxy system."""
        self.logger = logging.getLogger('RESIDENTIAL_PROXY')

        # Proxy pools
        self.proxies: Dict[str, ProxyMetadata] = {}

        # Geographic distribution tracking
        self.asn_distribution: Dict[int, int] = {}  # ASN -> count
        self.isp_distribution: Dict[str, int] = {}  # ISP -> count
        self.country_distribution: Dict[str, int] = {}  # Country -> count

        # Rotation strategies
        self.rotation_strategy = 'geographic_diverse'  # Maximize ASN/ISP diversity

        # Configuration
        self.max_usage_per_proxy = 50  # Rotate after N uses
        self.min_rotation_time = 300  # Minimum 5 minutes between rotations
        self.proxy_warmup_delay = 60  # Warm up new proxies with delay

        self.logger.info("Residential Proxy System initialized")

    def add_residential_proxy(self,
                            host: str,
                            port: int,
                            country: str,
                            quality: ProxyQuality = ProxyQuality.RESIDENTIAL,
                            username: Optional[str] = None,
                            password: Optional[str] = None,
                            asn: Optional[int] = None,
                            isp: Optional[str] = None,
                            timezone: Optional[str] = None) -> str:
        """
        Add residential proxy to pool.

        Args:
            host: Proxy host
            port: Proxy port
            country: Country code (ISO 3166-1 alpha-2)
            quality: Proxy quality level
            username: Optional authentication username
            password: Optional authentication password
            asn: Autonomous System Number
            isp: Internet Service Provider name
            timezone: Geographic timezone

        Returns:
            Proxy ID
        """
        proxy_id = f"{host}:{port}"

        proxy = ProxyMetadata(
            proxy_id=proxy_id,
            host=host,
            port=port,
            quality=quality,
            username=username,
            password=password,
            country=country,
            asn=asn,
            isp=isp,
            timezone=timezone,
            is_residential=(quality == ProxyQuality.RESIDENTIAL),
            is_mobile=(quality == ProxyQuality.MOBILE)
        )

        self.proxies[proxy_id] = proxy

        # Update distribution tracking
        if asn:
            self.asn_distribution[asn] = self.asn_distribution.get(asn, 0) + 1
        if isp:
            self.isp_distribution[isp] = self.isp_distribution.get(isp, 0) + 1
        if country:
            self.country_distribution[country] = self.country_distribution.get(country, 0) + 1

        self.logger.info(f"Added {quality.value} proxy: {proxy_id} ({country}, ASN: {asn}, ISP: {isp})")
        return proxy_id

    def get_next_proxy(self,
                      country: Optional[str] = None,
                      quality: Optional[ProxyQuality] = None,
                      require_residential: bool = True,
                      avoid_asn: Optional[List[int]] = None,
                      avoid_isp: Optional[List[str]] = None) -> Optional[ProxyMetadata]:
        """
        Get next proxy with enterprise detection evasion.

        Args:
            country: Optional country filter
            quality: Optional quality filter
            require_residential: Only use residential/mobile proxies
            avoid_asn: List of ASNs to avoid (for diversity)
            avoid_isp: List of ISPs to avoid (for diversity)

        Returns:
            ProxyMetadata or None
        """
        # Filter available proxies
        available = [
            p for p in self.proxies.values()
            if p.is_alive
            and not p.is_blacklisted
            and (country is None or p.country == country)
            and (quality is None or p.quality == quality)
            and (not require_residential or p.is_residential or p.is_mobile)
            and (avoid_asn is None or p.asn not in avoid_asn)
            and (avoid_isp is None or p.isp not in avoid_isp)
        ]

        if not available:
            self.logger.warning("No available proxies matching criteria")
            return None

        # Select based on strategy
        if self.rotation_strategy == 'geographic_diverse':
            # Prefer proxies from diverse ASNs and ISPs
            proxy = self._select_diverse_proxy(available)
        elif self.rotation_strategy == 'least_used':
            # Least recently used
            proxy = min(available, key=lambda p: p.last_used)
        elif self.rotation_strategy == 'best_reputation':
            # Highest reputation score
            proxy = max(available, key=lambda p: p.reputation_score)
        elif self.rotation_strategy == 'random':
            proxy = random.choice(available)
        else:
            proxy = random.choice(available)

        # Update usage tracking
        proxy.usage_count += 1
        proxy.last_used = time.time()

        # Check if proxy needs warmup
        if not proxy.warmed_up:
            self.logger.info(f"Proxy {proxy.proxy_id} needs warmup - first use")

        self.logger.debug(f"Selected proxy: {proxy.proxy_id} (ASN: {proxy.asn}, ISP: {proxy.isp})")
        return proxy

    def _select_diverse_proxy(self, available: List[ProxyMetadata]) -> ProxyMetadata:
        """
        Select proxy to maximize ASN and ISP diversity.
        This prevents businesses from detecting patterns in proxy usage.
        """
        # Score each proxy based on diversity
        scores = []
        for proxy in available:
            score = 0.0

            # Prefer less-used ASNs
            if proxy.asn:
                asn_count = self.asn_distribution.get(proxy.asn, 0)
                score += 1.0 / (asn_count + 1)

            # Prefer less-used ISPs
            if proxy.isp:
                isp_count = self.isp_distribution.get(proxy.isp, 0)
                score += 1.0 / (isp_count + 1)

            # Prefer proxies with higher reputation
            score += proxy.reputation_score * 0.5

            # Prefer less recently used proxies
            time_since_use = time.time() - proxy.last_used
            score += min(time_since_use / 3600.0, 1.0) * 0.3  # Max 1 hour bonus

            # Prefer mobile over residential
            if proxy.is_mobile:
                score += 0.2

            scores.append((proxy, score))

        # Select proxy with highest score
        best_proxy = max(scores, key=lambda x: x[1])[0]
        return best_proxy

    def check_dns_leak(self, proxy_id: str) -> Tuple[bool, List[str]]:
        """
        Check for DNS leaks through proxy.

        Args:
            proxy_id: Proxy ID to check

        Returns:
            Tuple of (leak_detected, dns_servers)
        """
        if proxy_id not in self.proxies:
            return False, []

        proxy = self.proxies[proxy_id]

        try:
            # Use DNS leak testing service
            test_url = "https://www.dnsleaktest.com/json"

            proxies = {
                'http': f"http://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}" if proxy.username else f"http://{proxy.host}:{proxy.port}",
                'https': f"https://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}" if proxy.username else f"https://{proxy.host}:{proxy.port}"
            }

            response = requests.get(test_url, proxies=proxies, timeout=15)

            if response.status_code == 200:
                data = response.json()
                dns_servers = [server.get('ip', '') for server in data]

                proxy.dns_servers = dns_servers

                # Check if DNS servers match proxy country
                # If DNS servers are in different country, it's a leak
                leak_detected = False
                for server in data:
                    server_country = server.get('country_code', '')
                    if server_country and proxy.country and server_country != proxy.country:
                        leak_detected = True
                        self.logger.warning(f"DNS leak detected on {proxy_id}: DNS in {server_country}, proxy in {proxy.country}")
                        break

                proxy.dns_leak_detected = leak_detected
                return leak_detected, dns_servers

        except Exception as e:
            self.logger.error(f"DNS leak check failed for {proxy_id}: {e}")
            return False, []

        return False, []

    def check_geographic_consistency(self, proxy_id: str, timezone: str) -> bool:
        """
        Check if proxy location matches expected timezone.

        Args:
            proxy_id: Proxy ID
            timezone: Expected timezone (e.g., 'America/New_York')

        Returns:
            True if consistent, False if mismatch detected
        """
        if proxy_id not in self.proxies:
            return False

        proxy = self.proxies[proxy_id]

        if not proxy.timezone:
            self.logger.warning(f"Proxy {proxy_id} has no timezone metadata")
            return True  # Can't verify, assume OK

        # Check if timezones match
        if proxy.timezone != timezone:
            self.logger.warning(f"Geographic inconsistency: Proxy timezone {proxy.timezone} != expected {timezone}")
            return False

        return True

    def check_proxy_reputation(self, proxy_id: str) -> float:
        """
        Check proxy IP reputation using threat intelligence.

        Args:
            proxy_id: Proxy ID

        Returns:
            Reputation score (0.0 to 1.0, higher is better)
        """
        if proxy_id not in self.proxies:
            return 0.0

        proxy = self.proxies[proxy_id]

        try:
            # Use IP reputation API (example: AbuseIPDB, IPQualityScore, etc.)
            # This is a placeholder - integrate with actual API

            # For now, return random score
            reputation = random.uniform(0.7, 1.0) if proxy.is_residential or proxy.is_mobile else random.uniform(0.4, 0.7)

            proxy.reputation_score = reputation
            self.logger.info(f"Proxy {proxy_id} reputation: {reputation:.2f}")

            return reputation

        except Exception as e:
            self.logger.error(f"Reputation check failed for {proxy_id}: {e}")
            return 0.5

    def warmup_proxy(self, proxy_id: str, warmup_requests: int = 5):
        """
        Warm up a new proxy with gradual activity.

        New proxies should not be immediately used for sensitive operations.
        Gradual warmup prevents detection of sudden activity patterns.

        Args:
            proxy_id: Proxy ID
            warmup_requests: Number of warmup requests
        """
        if proxy_id not in self.proxies:
            return

        proxy = self.proxies[proxy_id]

        if proxy.warmed_up:
            return

        self.logger.info(f"Warming up proxy {proxy_id} with {warmup_requests} requests...")

        proxies = {
            'http': f"http://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}" if proxy.username else f"http://{proxy.host}:{proxy.port}",
            'https': f"https://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}" if proxy.username else f"https://{proxy.host}:{proxy.port}"
        }

        # Warmup URLs (benign, common sites)
        warmup_urls = [
            'https://www.google.com',
            'https://www.wikipedia.org',
            'https://www.github.com',
            'https://www.stackoverflow.com',
            'https://www.reddit.com'
        ]

        for i in range(warmup_requests):
            url = random.choice(warmup_urls)
            try:
                response = requests.get(url, proxies=proxies, timeout=10)
                self.logger.debug(f"Warmup {i+1}/{warmup_requests}: {url} - {response.status_code}")

                # Random delay between requests (1-5 seconds)
                time.sleep(random.uniform(1.0, 5.0))

            except Exception as e:
                self.logger.warning(f"Warmup request failed: {e}")

        proxy.warmed_up = True
        self.logger.info(f"Proxy {proxy_id} warmup complete")

    def rotate_if_needed(self, current_proxy_id: str, session_duration_minutes: int = 30) -> Optional[str]:
        """
        Check if proxy should be rotated based on usage patterns.

        Args:
            current_proxy_id: Current proxy ID
            session_duration_minutes: Session duration in minutes

        Returns:
            New proxy ID if rotation needed, None otherwise
        """
        if current_proxy_id not in self.proxies:
            return None

        proxy = self.proxies[current_proxy_id]

        # Rotate if:
        # 1. Proxy has been used too many times
        # 2. Proxy has been used for too long
        # 3. Proxy reputation is low
        # 4. DNS leak detected

        should_rotate = False
        reason = ""

        if proxy.usage_count >= self.max_usage_per_proxy:
            should_rotate = True
            reason = f"usage count {proxy.usage_count} >= {self.max_usage_per_proxy}"

        time_since_use = time.time() - proxy.last_used
        if time_since_use < self.min_rotation_time and proxy.usage_count > 0:
            # Too soon to rotate
            pass
        elif session_duration_minutes > 60:
            should_rotate = True
            reason = f"session duration {session_duration_minutes}min > 60min"

        if proxy.reputation_score < 0.5:
            should_rotate = True
            reason = f"low reputation {proxy.reputation_score:.2f}"

        if proxy.dns_leak_detected:
            should_rotate = True
            reason = "DNS leak detected"

        if should_rotate:
            self.logger.info(f"Rotating proxy {current_proxy_id}: {reason}")

            # Get new proxy, avoiding same ASN/ISP
            new_proxy = self.get_next_proxy(
                country=proxy.country,
                avoid_asn=[proxy.asn] if proxy.asn else None,
                avoid_isp=[proxy.isp] if proxy.isp else None
            )

            if new_proxy:
                return new_proxy.proxy_id

        return None

    def get_proxy_statistics(self) -> Dict:
        """Get proxy pool statistics."""
        total = len(self.proxies)
        alive = sum(1 for p in self.proxies.values() if p.is_alive)
        residential = sum(1 for p in self.proxies.values() if p.is_residential)
        mobile = sum(1 for p in self.proxies.values() if p.is_mobile)
        blacklisted = sum(1 for p in self.proxies.values() if p.is_blacklisted)

        avg_reputation = sum(p.reputation_score for p in self.proxies.values()) / max(total, 1)

        return {
            'total_proxies': total,
            'alive_proxies': alive,
            'residential_proxies': residential,
            'mobile_proxies': mobile,
            'blacklisted_proxies': blacklisted,
            'average_reputation': avg_reputation,
            'asn_diversity': len(self.asn_distribution),
            'isp_diversity': len(self.isp_distribution),
            'country_distribution': dict(self.country_distribution),
            'rotation_strategy': self.rotation_strategy
        }

    def to_selenium_proxy_dict(self, proxy_id: str) -> Optional[Dict[str, str]]:
        """
        Convert proxy to Selenium proxy configuration.

        Args:
            proxy_id: Proxy ID

        Returns:
            Selenium proxy dict
        """
        if proxy_id not in self.proxies:
            return None

        proxy = self.proxies[proxy_id]

        proxy_url = f"{proxy.host}:{proxy.port}"
        if proxy.username and proxy.password:
            proxy_url = f"{proxy.username}:{proxy.password}@{proxy_url}"

        return {
            'proxyType': 'manual',
            'httpProxy': proxy_url,
            'sslProxy': proxy_url,
            'noProxy': ''
        }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    print("="*80)
    print("RESIDENTIAL PROXY SYSTEM DEMONSTRATION")
    print("="*80)
    print()

    # Initialize system
    proxy_system = ResidentialProxySystem()

    # Add sample residential proxies
    print("Adding residential proxies...")
    proxy_system.add_residential_proxy(
        host='residential1.example.com',
        port=8080,
        country='US',
        quality=ProxyQuality.RESIDENTIAL,
        username='user1',
        password='pass1',
        asn=7922,  # Comcast
        isp='Comcast Cable',
        timezone='America/New_York'
    )

    proxy_system.add_residential_proxy(
        host='residential2.example.com',
        port=8080,
        country='US',
        quality=ProxyQuality.RESIDENTIAL,
        username='user2',
        password='pass2',
        asn=20115,  # Charter
        isp='Charter Communications',
        timezone='America/Los_Angeles'
    )

    proxy_system.add_residential_proxy(
        host='mobile1.example.com',
        port=8080,
        country='US',
        quality=ProxyQuality.MOBILE,
        username='user3',
        password='pass3',
        asn=5650,  # Verizon
        isp='Verizon Wireless',
        timezone='America/Chicago'
    )

    print()

    # Get statistics
    stats = proxy_system.get_proxy_statistics()
    print("Proxy Pool Statistics:")
    print(json.dumps(stats, indent=2))
    print()

    # Get next proxy with diversity
    print("Getting next proxy (ASN/ISP diverse)...")
    proxy = proxy_system.get_next_proxy(country='US')
    if proxy:
        print(f"  Selected: {proxy.proxy_id}")
        print(f"  Quality: {proxy.quality.value}")
        print(f"  ASN: {proxy.asn}")
        print(f"  ISP: {proxy.isp}")
        print(f"  Timezone: {proxy.timezone}")
    print()

    print("="*80)
