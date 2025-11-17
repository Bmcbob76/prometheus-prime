#!/usr/bin/env python3
"""
PROMETHEUS PRIME - PROXY MANAGER
Rotating proxy management for anti-detect browser sessions

Authority Level: 11.0
Commander: Bobby Don McWilliams II

Features:
  - SOCKS5/HTTP/HTTPS proxy support
  - Automatic proxy rotation
  - Proxy health checking
  - GeoIP-based proxy selection
  - Tor integration
  - Residential/datacenter proxy pools
"""

import requests
import random
import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class ProxyType(Enum):
    """Proxy protocol types."""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    TOR = "tor"


class ProxySource(Enum):
    """Proxy source types."""
    RESIDENTIAL = "residential"
    DATACENTER = "datacenter"
    MOBILE = "mobile"
    TOR = "tor"


@dataclass
class ProxyServer:
    """Proxy server configuration."""
    proxy_id: str
    host: str
    port: int
    proxy_type: ProxyType
    source: ProxySource

    username: Optional[str] = None
    password: Optional[str] = None

    country: Optional[str] = None
    city: Optional[str] = None

    response_time_ms: float = 0.0
    success_rate: float = 1.0
    last_checked: float = 0.0
    is_alive: bool = True

    def to_url(self) -> str:
        """Convert to proxy URL format."""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        else:
            auth = ""

        return f"{self.proxy_type.value}://{auth}{self.host}:{self.port}"

    def to_dict(self) -> Dict[str, str]:
        """Convert to selenium proxy dict."""
        return {
            'proxyType': 'manual',
            'httpProxy': f"{self.host}:{self.port}",
            'sslProxy': f"{self.host}:{self.port}",
            'socksProxy': f"{self.host}:{self.port}" if 'socks' in self.proxy_type.value else None
        }


class ProxyManager:
    """
    Proxy rotation manager for anti-detect browsers.
    Manages pools of proxies with automatic rotation and health checking.
    """

    def __init__(self):
        """Initialize proxy manager."""
        self.logger = logging.getLogger('PROXY_MANAGER')

        # Proxy pools
        self.proxies: Dict[str, ProxyServer] = {}

        # Usage tracking
        self.usage_count: Dict[str, int] = {}
        self.last_used: Dict[str, float] = {}

        # Configuration
        self.rotation_strategy = 'round_robin'  # round_robin, random, least_used

        self.logger.info("Proxy Manager initialized")

    def add_proxy(self,
                  host: str,
                  port: int,
                  proxy_type: ProxyType = ProxyType.HTTP,
                  source: ProxySource = ProxySource.DATACENTER,
                  username: Optional[str] = None,
                  password: Optional[str] = None,
                  country: Optional[str] = None) -> str:
        """
        Add a proxy to the pool.

        Args:
            host: Proxy hostname/IP
            port: Proxy port
            proxy_type: Proxy protocol type
            source: Proxy source type
            username: Optional authentication username
            password: Optional authentication password
            country: Optional country code

        Returns:
            Proxy ID
        """
        proxy_id = f"{host}:{port}"

        proxy = ProxyServer(
            proxy_id=proxy_id,
            host=host,
            port=port,
            proxy_type=proxy_type,
            source=source,
            username=username,
            password=password,
            country=country
        )

        self.proxies[proxy_id] = proxy
        self.usage_count[proxy_id] = 0
        self.last_used[proxy_id] = 0.0

        self.logger.info(f"Added proxy: {proxy_id} ({proxy_type.value}/{source.value})")
        return proxy_id

    def add_proxy_list(self, proxy_list: List[str]):
        """
        Add multiple proxies from list.

        Args:
            proxy_list: List of proxy strings (host:port or user:pass@host:port)
        """
        for proxy_str in proxy_list:
            try:
                # Parse proxy string
                if '@' in proxy_str:
                    auth, server = proxy_str.split('@')
                    username, password = auth.split(':')
                    host, port = server.split(':')
                else:
                    host, port = proxy_str.split(':')
                    username, password = None, None

                self.add_proxy(
                    host=host,
                    port=int(port),
                    username=username,
                    password=password
                )
            except Exception as e:
                self.logger.error(f"Failed to parse proxy {proxy_str}: {e}")

    def get_next_proxy(self,
                      country: Optional[str] = None,
                      source: Optional[ProxySource] = None) -> Optional[ProxyServer]:
        """
        Get next proxy from pool using rotation strategy.

        Args:
            country: Optional country filter
            source: Optional source type filter

        Returns:
            ProxyServer or None
        """
        # Filter proxies
        available_proxies = [
            p for p in self.proxies.values()
            if p.is_alive and
            (country is None or p.country == country) and
            (source is None or p.source == source)
        ]

        if not available_proxies:
            self.logger.warning("No available proxies in pool")
            return None

        # Select proxy based on strategy
        if self.rotation_strategy == 'round_robin':
            proxy = min(available_proxies, key=lambda p: self.usage_count.get(p.proxy_id, 0))
        elif self.rotation_strategy == 'random':
            proxy = random.choice(available_proxies)
        elif self.rotation_strategy == 'least_used':
            proxy = min(available_proxies, key=lambda p: self.last_used.get(p.proxy_id, 0))
        else:
            proxy = random.choice(available_proxies)

        # Update usage tracking
        self.usage_count[proxy.proxy_id] += 1
        self.last_used[proxy.proxy_id] = time.time()

        self.logger.debug(f"Selected proxy: {proxy.proxy_id}")
        return proxy

    def check_proxy_health(self, proxy_id: str, test_url: str = "https://api.ipify.org?format=json") -> bool:
        """
        Check if proxy is alive and working.

        Args:
            proxy_id: Proxy ID to check
            test_url: URL to test proxy against

        Returns:
            True if proxy is working
        """
        if proxy_id not in self.proxies:
            return False

        proxy = self.proxies[proxy_id]

        try:
            start_time = time.time()

            proxies = {
                'http': proxy.to_url(),
                'https': proxy.to_url()
            }

            response = requests.get(
                test_url,
                proxies=proxies,
                timeout=10
            )

            response_time = (time.time() - start_time) * 1000

            if response.status_code == 200:
                proxy.response_time_ms = response_time
                proxy.is_alive = True
                proxy.last_checked = time.time()

                # Get IP
                try:
                    data = response.json()
                    ip = data.get('ip', 'unknown')
                    self.logger.info(f"Proxy {proxy_id} is alive (IP: {ip}, {response_time:.0f}ms)")
                except:
                    self.logger.info(f"Proxy {proxy_id} is alive ({response_time:.0f}ms)")

                return True
            else:
                proxy.is_alive = False
                self.logger.warning(f"Proxy {proxy_id} returned status {response.status_code}")
                return False

        except Exception as e:
            proxy.is_alive = False
            proxy.last_checked = time.time()
            self.logger.error(f"Proxy {proxy_id} health check failed: {e}")
            return False

    def check_all_proxies(self):
        """Check health of all proxies in pool."""
        self.logger.info("Checking health of all proxies...")

        for proxy_id in self.proxies.keys():
            self.check_proxy_health(proxy_id)
            time.sleep(0.5)  # Small delay between checks

        alive_count = sum(1 for p in self.proxies.values() if p.is_alive)
        self.logger.info(f"Proxy health check complete: {alive_count}/{len(self.proxies)} alive")

    def setup_tor(self,
                  tor_socks_port: int = 9050,
                  tor_control_port: int = 9051,
                  tor_password: Optional[str] = None):
        """
        Add Tor proxy to pool.

        Args:
            tor_socks_port: Tor SOCKS port (default 9050)
            tor_control_port: Tor control port (default 9051)
            tor_password: Tor control password
        """
        self.add_proxy(
            host='127.0.0.1',
            port=tor_socks_port,
            proxy_type=ProxyType.SOCKS5,
            source=ProxySource.TOR
        )

        self.logger.info(f"Tor proxy added (SOCKS5 port {tor_socks_port})")

    def rotate_tor_identity(self):
        """Request new Tor identity (new circuit)."""
        try:
            from stem import Signal
            from stem.control import Controller

            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                self.logger.info("Tor identity rotated (new circuit)")
                time.sleep(5)  # Wait for new circuit
                return True

        except ImportError:
            self.logger.error("Stem library not available - install with: pip install stem")
            return False
        except Exception as e:
            self.logger.error(f"Failed to rotate Tor identity: {e}")
            return False

    def get_statistics(self) -> Dict:
        """Get proxy pool statistics."""
        total = len(self.proxies)
        alive = sum(1 for p in self.proxies.values() if p.is_alive)

        by_source = {}
        by_country = {}

        for proxy in self.proxies.values():
            # By source
            source = proxy.source.value
            by_source[source] = by_source.get(source, 0) + 1

            # By country
            if proxy.country:
                by_country[proxy.country] = by_country.get(proxy.country, 0) + 1

        return {
            'total_proxies': total,
            'alive_proxies': alive,
            'dead_proxies': total - alive,
            'by_source': by_source,
            'by_country': by_country,
            'rotation_strategy': self.rotation_strategy
        }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    print("="*80)
    print("PROXY MANAGER DEMONSTRATION")
    print("="*80)
    print()

    # Initialize proxy manager
    manager = ProxyManager()

    # Add some example proxies (these are fake - use real proxies in production)
    print("Adding example proxies...")
    manager.add_proxy('proxy1.example.com', 8080, country='US')
    manager.add_proxy('proxy2.example.com', 8080, country='UK')
    manager.add_proxy('proxy3.example.com', 8080, country='DE')
    print()

    # Add Tor
    print("Adding Tor proxy...")
    manager.setup_tor()
    print()

    # Get statistics
    print("Proxy Pool Statistics:")
    import json
    print(json.dumps(manager.get_statistics(), indent=2))
    print()

    # Get next proxy
    print("Getting next proxy (round-robin)...")
    proxy = manager.get_next_proxy()
    if proxy:
        print(f"  Selected: {proxy.proxy_id}")
        print(f"  URL: {proxy.to_url()}")
    print()

    print("="*80)
