"""
Compatibility Matrix - Learning Database for Package Combinations
==================================================================

This system learns which package version combinations work together successfully
and provides recommendations when conflicts arise.

Features:
- Records successful package combinations
- Tracks Python version compatibility
- Provides conflict resolution recommendations
- Learning from historical success/failure

Version: 1.0.0 (Phase 3)
"""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
import sys


@dataclass
class PackageCombination:
    """A record of successfully working package versions"""
    packages: Dict[str, str]  # package_name -> version
    python_version: str
    timestamp: str
    success_count: int = 1
    failure_count: int = 0
    last_verified: Optional[str] = None
    environment_hash: str = ""


class CompatibilityMatrix:
    """
    Learning database that tracks successful package combinations.

    Uses this data to recommend compatible versions when conflicts arise.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path(__file__).parent.parent.parent / 'data' / 'compatibility_matrix.json'
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # In-memory database
        self.combinations: Dict[str, PackageCombination] = {}

        # Quick lookup indices
        self.package_index: Dict[str, Set[str]] = {}  # package_name -> set of combo_hashes

        self.load_database()

    def _hash_combination(self, packages: Dict[str, str]) -> str:
        """Create unique hash for package combination"""
        # Sort packages for consistent hashing
        sorted_packages = sorted(packages.items())
        content = json.dumps(sorted_packages, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def record_success(self, packages: Dict[str, str], python_version: Optional[str] = None):
        """Record a successful package combination"""
        if not packages:
            return

        py_version = python_version or f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        combo_hash = self._hash_combination(packages)

        if combo_hash in self.combinations:
            # Update existing record
            combo = self.combinations[combo_hash]
            combo.success_count += 1
            combo.last_verified = datetime.now().isoformat()
        else:
            # Create new record
            combo = PackageCombination(
                packages=packages,
                python_version=py_version,
                timestamp=datetime.now().isoformat(),
                success_count=1,
                last_verified=datetime.now().isoformat(),
                environment_hash=combo_hash
            )
            self.combinations[combo_hash] = combo

            # Update index
            for pkg_name in packages.keys():
                if pkg_name not in self.package_index:
                    self.package_index[pkg_name] = set()
                self.package_index[pkg_name].add(combo_hash)

        self.save_database()

    def record_failure(self, packages: Dict[str, str]):
        """Record a failed package combination"""
        if not packages:
            return

        combo_hash = self._hash_combination(packages)

        if combo_hash in self.combinations:
            self.combinations[combo_hash].failure_count += 1
            self.save_database()

    def find_compatible_set(self, target_packages: List[str], current_versions: Optional[Dict[str, str]] = None) -> Optional[Dict[str, str]]:
        """
        Find a known-working combination that includes the target packages.

        Args:
            target_packages: List of package names that must be included
            current_versions: Current installed versions (optional)

        Returns:
            Dict of package_name -> version that is known to work, or None
        """
        # Find all combinations that include ALL target packages
        candidate_combos = None

        for pkg_name in target_packages:
            if pkg_name not in self.package_index:
                # Package not in our database
                continue

            combo_hashes = self.package_index[pkg_name]

            if candidate_combos is None:
                candidate_combos = combo_hashes.copy()
            else:
                candidate_combos &= combo_hashes  # Intersection

        if not candidate_combos:
            return None

        # Get all matching combinations and sort by success rate and recency
        matching_combos = [self.combinations[h] for h in candidate_combos]
        matching_combos.sort(
            key=lambda c: (
                c.success_count / max(c.failure_count + c.success_count, 1),  # Success rate
                c.last_verified or c.timestamp  # Recency
            ),
            reverse=True
        )

        # Return the best combination
        if matching_combos:
            return matching_combos[0].packages

        return None

    def get_version_recommendations(self, package_name: str) -> List[Tuple[str, int]]:
        """
        Get recommended versions for a package based on success history.

        Returns list of (version, success_count) tuples
        """
        if package_name not in self.package_index:
            return []

        version_counts: Dict[str, int] = {}

        for combo_hash in self.package_index[package_name]:
            combo = self.combinations[combo_hash]
            if package_name in combo.packages:
                version = combo.packages[package_name]
                version_counts[version] = version_counts.get(version, 0) + combo.success_count

        # Sort by success count
        recommendations = sorted(version_counts.items(), key=lambda x: x[1], reverse=True)
        return recommendations

    def check_conflict(self, pkg1: str, pkg2: str, version1: Optional[str] = None, version2: Optional[str] = None) -> bool:
        """
        Check if two packages have known conflicts.

        Returns True if conflict detected, False otherwise
        """
        # Find combinations with both packages
        if pkg1 not in self.package_index or pkg2 not in self.package_index:
            return False  # Unknown

        combo_hashes = self.package_index[pkg1] & self.package_index[pkg2]

        if not combo_hashes:
            # No recorded combinations with both packages - potential conflict
            return True

        # Check if any successful combinations exist
        for combo_hash in combo_hashes:
            combo = self.combinations[combo_hash]

            # Check if versions match if specified
            if version1 and combo.packages.get(pkg1) != version1:
                continue
            if version2 and combo.packages.get(pkg2) != version2:
                continue

            # If we found a successful combo, no conflict
            if combo.success_count > combo.failure_count:
                return False

        return True  # No successful combination found

    def get_stats(self) -> Dict:
        """Get statistics about the compatibility database"""
        total_combos = len(self.combinations)
        total_packages = len(self.package_index)

        successful_combos = sum(1 for c in self.combinations.values() if c.success_count > c.failure_count)

        return {
            'total_combinations': total_combos,
            'successful_combinations': successful_combos,
            'tracked_packages': total_packages,
            'success_rate': successful_combos / max(total_combos, 1) * 100,
        }

    def load_database(self):
        """Load compatibility database from file"""
        if not self.db_path.exists():
            return

        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)

            for combo_hash, combo_data in data.items():
                combo = PackageCombination(**combo_data)
                self.combinations[combo_hash] = combo

                # Rebuild index
                for pkg_name in combo.packages.keys():
                    if pkg_name not in self.package_index:
                        self.package_index[pkg_name] = set()
                    self.package_index[pkg_name].add(combo_hash)

            print(f"[COMPATIBILITY] Loaded {len(self.combinations)} package combinations")

        except Exception as e:
            print(f"[COMPATIBILITY] Error loading database: {e}")

    def save_database(self):
        """Save compatibility database to file"""
        try:
            data = {}
            for combo_hash, combo in self.combinations.items():
                data[combo_hash] = asdict(combo)

            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"[COMPATIBILITY] Error saving database: {e}")

    def clear_old_records(self, days: int = 90):
        """Clear records older than specified days"""
        from datetime import datetime, timedelta

        cutoff = datetime.now() - timedelta(days=days)
        cutoff_iso = cutoff.isoformat()

        to_remove = []
        for combo_hash, combo in self.combinations.items():
            if (combo.last_verified or combo.timestamp) < cutoff_iso:
                to_remove.append(combo_hash)

        for combo_hash in to_remove:
            combo = self.combinations[combo_hash]
            # Remove from index
            for pkg_name in combo.packages.keys():
                if pkg_name in self.package_index:
                    self.package_index[pkg_name].discard(combo_hash)
            # Remove from database
            del self.combinations[combo_hash]

        if to_remove:
            print(f"[COMPATIBILITY] Removed {len(to_remove)} old records")
            self.save_database()
