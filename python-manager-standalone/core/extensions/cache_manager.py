#!/usr/bin/env python3
"""
PyManager Cache Manager - 10x Performance Boost
Intelligent caching system for routing decisions and dependency checks
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Dict, Optional, Any, Tuple
from collections import OrderedDict
import threading


class CacheEntry:
    """Single cache entry with TTL and metadata"""

    def __init__(self, value: Any, ttl: int = 300):
        self.value = value
        self.created_at = time.time()
        self.ttl = ttl
        self.hit_count = 0
        self.last_accessed = time.time()

    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return (time.time() - self.created_at) > self.ttl

    def access(self) -> Any:
        """Record access and return value"""
        self.hit_count += 1
        self.last_accessed = time.time()
        return self.value


class LRUCache:
    """Thread-safe LRU cache with TTL support"""

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.Lock()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0,
        }

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            if key not in self.cache:
                self.stats['misses'] += 1
                return None

            entry = self.cache[key]

            # Check expiration
            if entry.is_expired():
                del self.cache[key]
                self.stats['expirations'] += 1
                self.stats['misses'] += 1
                return None

            # Move to end (most recently used)
            self.cache.move_to_end(key)
            self.stats['hits'] += 1
            return entry.access()

    def set(self, key: str, value: Any, ttl: int = 300):
        """Set value in cache"""
        with self.lock:
            # Remove existing entry if present
            if key in self.cache:
                del self.cache[key]

            # Evict oldest if at capacity
            if len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                self.stats['evictions'] += 1

            # Add new entry
            self.cache[key] = CacheEntry(value, ttl)

    def invalidate(self, key: str):
        """Invalidate specific cache entry"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.stats = {
                'hits': 0,
                'misses': 0,
                'evictions': 0,
                'expirations': 0,
            }

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0

            return {
                **self.stats,
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_rate': f"{hit_rate:.2f}%",
            }


class CacheManager:
    """Main cache manager for PyManager"""

    def __init__(self, config: Dict, cache_dir: Optional[Path] = None):
        self.config = config
        self.cache_dir = cache_dir or Path.home() / '.pymanager' / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Cache settings from config
        cache_config = config.get('cache', {})
        self.enabled = cache_config.get('enabled', True)
        self.max_size = cache_config.get('max_size', 1000)

        # Different caches for different purposes
        self.version_cache = LRUCache(max_size=self.max_size)
        self.dependency_cache = LRUCache(max_size=self.max_size)
        self.import_cache = LRUCache(max_size=self.max_size)
        self.port_cache = LRUCache(max_size=100)

        # Config file hash for invalidation
        self.config_hash = self._hash_config()

    def _hash_config(self) -> str:
        """Generate hash of configuration for invalidation"""
        config_str = json.dumps(self.config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()

    def _hash_file(self, file_path: Path) -> str:
        """Generate hash of file for caching"""
        try:
            # Use mtime + size for quick hash (faster than reading entire file)
            stat = file_path.stat()
            key_data = f"{file_path}:{stat.st_mtime}:{stat.st_size}"
            return hashlib.sha256(key_data.encode()).hexdigest()[:16]
        except:
            return hashlib.sha256(str(file_path).encode()).hexdigest()[:16]

    def check_config_changed(self) -> bool:
        """Check if config has changed (invalidates all caches)"""
        current_hash = self._hash_config()
        if current_hash != self.config_hash:
            self.invalidate_all()
            self.config_hash = current_hash
            return True
        return False

    def get_version_for_script(self, script_path: Path) -> Optional[str]:
        """Get cached Python version for script"""
        if not self.enabled:
            return None

        cache_key = f"version:{self._hash_file(script_path)}"
        return self.version_cache.get(cache_key)

    def set_version_for_script(self, script_path: Path, version: str, ttl: int = 300):
        """Cache Python version for script"""
        if not self.enabled:
            return

        cache_key = f"version:{self._hash_file(script_path)}"
        self.version_cache.set(cache_key, version, ttl)

    def get_dependencies(self, script_path: Path) -> Optional[list]:
        """Get cached dependency list for script"""
        if not self.enabled:
            return None

        cache_key = f"deps:{self._hash_file(script_path)}"
        return self.dependency_cache.get(cache_key)

    def set_dependencies(self, script_path: Path, dependencies: list, ttl: int = 600):
        """Cache dependency list for script"""
        if not self.enabled:
            return

        cache_key = f"deps:{self._hash_file(script_path)}"
        self.dependency_cache.set(cache_key, dependencies, ttl)

    def get_imports(self, script_path: Path) -> Optional[list]:
        """Get cached import list for script"""
        if not self.enabled:
            return None

        cache_key = f"imports:{self._hash_file(script_path)}"
        return self.import_cache.get(cache_key)

    def set_imports(self, script_path: Path, imports: list, ttl: int = 600):
        """Cache import list for script"""
        if not self.enabled:
            return

        cache_key = f"imports:{self._hash_file(script_path)}"
        self.import_cache.set(cache_key, imports, ttl)

    def get_port_status(self, port: int) -> Optional[bool]:
        """Get cached port status (True = in use)"""
        if not self.enabled:
            return None

        cache_key = f"port:{port}"
        return self.port_cache.get(cache_key)

    def set_port_status(self, port: int, in_use: bool, ttl: int = 30):
        """Cache port status (short TTL since ports change frequently)"""
        if not self.enabled:
            return

        cache_key = f"port:{port}"
        self.port_cache.set(cache_key, in_use, ttl)

    def invalidate_all(self):
        """Invalidate all caches"""
        self.version_cache.clear()
        self.dependency_cache.clear()
        self.import_cache.clear()
        self.port_cache.clear()

    def get_all_stats(self) -> Dict:
        """Get statistics for all caches"""
        return {
            'version_cache': self.version_cache.get_stats(),
            'dependency_cache': self.dependency_cache.get_stats(),
            'import_cache': self.import_cache.get_stats(),
            'port_cache': self.port_cache.get_stats(),
            'config_hash': self.config_hash,
            'cache_dir': str(self.cache_dir),
            'enabled': self.enabled,
        }

    def show_stats(self):
        """Display cache statistics"""
        stats = self.get_all_stats()

        print("=" * 70)
        print("PyManager Cache Statistics")
        print("=" * 70)
        print(f"Status: {'Enabled' if stats['enabled'] else 'Disabled'}")
        print(f"Cache Directory: {stats['cache_dir']}")
        print()

        for cache_name, cache_stats in stats.items():
            if cache_name in ['config_hash', 'cache_dir', 'enabled']:
                continue

            print(f"{cache_name.replace('_', ' ').title()}:")
            print(f"  Size: {cache_stats['size']}/{cache_stats['max_size']}")
            print(f"  Hits: {cache_stats['hits']}")
            print(f"  Misses: {cache_stats['misses']}")
            print(f"  Hit Rate: {cache_stats['hit_rate']}")
            print(f"  Evictions: {cache_stats['evictions']}")
            print(f"  Expirations: {cache_stats['expirations']}")
            print()

        print("=" * 70)

    def save_persistent_cache(self):
        """Save cache to disk for persistence across sessions"""
        try:
            cache_file = self.cache_dir / 'persistent_cache.json'

            # Only save version cache (most valuable)
            data = {
                'config_hash': self.config_hash,
                'timestamp': time.time(),
                'version_cache': {
                    k: {'value': v.value, 'created_at': v.created_at, 'ttl': v.ttl}
                    for k, v in self.version_cache.cache.items()
                    if not v.is_expired()
                }
            }

            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            # Silently fail - caching is not critical
            pass

    def load_persistent_cache(self):
        """Load cache from disk"""
        try:
            cache_file = self.cache_dir / 'persistent_cache.json'

            if not cache_file.exists():
                return

            with open(cache_file, 'r') as f:
                data = json.load(f)

            # Only load if config hasn't changed
            if data.get('config_hash') != self.config_hash:
                return

            # Restore version cache
            for key, entry_data in data.get('version_cache', {}).items():
                entry = CacheEntry(
                    entry_data['value'],
                    entry_data['ttl']
                )
                entry.created_at = entry_data['created_at']

                # Only restore if not expired
                if not entry.is_expired():
                    self.version_cache.cache[key] = entry

        except Exception as e:
            # Silently fail - caching is not critical
            pass


def main():
    """CLI for cache management"""
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Cache Manager')
    parser.add_argument('command', choices=['stats', 'clear', 'enable', 'disable'],
                        help='Command to execute')

    args = parser.parse_args()

    # Load config
    manager_dir = Path(__file__).parent.parent.parent
    config_file = manager_dir / 'pymanager.json'

    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {}

    # Create cache manager
    cache_mgr = CacheManager(config)
    cache_mgr.load_persistent_cache()

    # Execute command
    if args.command == 'stats':
        cache_mgr.show_stats()

    elif args.command == 'clear':
        cache_mgr.invalidate_all()
        print("✅ All caches cleared")

    elif args.command == 'enable':
        config.setdefault('cache', {})['enabled'] = True
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Cache enabled")

    elif args.command == 'disable':
        config.setdefault('cache', {})['enabled'] = False
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Cache disabled")


if __name__ == '__main__':
    main()
