#!/usr/bin/env python3
"""
Crystal Memory Hub - Multi-Path Search Logic
Fixed to search all crystal locations: CRYSTALS_NEW, L3_Crystals, L9_EKM, MASTER_EKM
Authority Level: 11.0
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any
import re
from datetime import datetime

class CrystalSearchFixed:
    """Fixed crystal search with multi-path support"""

    def __init__(self, config_path: str = "mls_config.json"):
        """Initialize with config file"""
        self.config = self.load_config(config_path)
        self.search_paths = self.get_all_search_paths()
        print(f"✅ Crystal Search initialized with {len(self.search_paths)} search locations")
        for path_info in self.search_paths:
            print(f"   📁 {path_info['name']}: {path_info['path']}")

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"⚠️  Config file not found: {config_path}")
            return {}

    def get_all_search_paths(self) -> List[Dict[str, Any]]:
        """Get all search paths from config (multi-path or legacy)"""
        paths = []

        # Try new multi-path config first
        if "search_paths" in self.config:
            # M: drive paths
            if "m_drive" in self.config["search_paths"]:
                paths.extend(self.config["search_paths"]["m_drive"])

            # G: drive paths
            if "g_drive" in self.config["search_paths"]:
                paths.extend(self.config["search_paths"]["g_drive"])

        # Fallback to legacy single-path config
        elif "legacy_paths" in self.config:
            legacy = self.config["legacy_paths"]
            if "m_drive_path" in legacy:
                paths.append({
                    "name": "m_drive_legacy",
                    "path": legacy["m_drive_path"],
                    "pattern": "*.md",
                    "priority": 1
                })
            if "g_drive_path" in legacy:
                paths.append({
                    "name": "g_drive_legacy",
                    "path": legacy["g_drive_path"],
                    "pattern": "*.md",
                    "priority": 2
                })

        # Sort by priority
        paths.sort(key=lambda x: x.get("priority", 999))
        return paths

    def search_crystals(self, query: str, drive: str = "ALL", limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search crystals across all configured paths

        Args:
            query: Search query string
            drive: "M", "G", or "ALL" (default: "ALL")
            limit: Maximum results to return (default: 100)

        Returns:
            List of matching crystal results
        """
        results = []
        query_lower = query.lower()

        # Filter paths by drive if specified
        search_paths = self.search_paths
        if drive == "M":
            search_paths = [p for p in search_paths if p["path"].startswith("M:")]
        elif drive == "G":
            search_paths = [p for p in search_paths if p["path"].startswith("G:")]

        print(f"\n🔍 Searching {len(search_paths)} locations for: '{query}'")

        for path_info in search_paths:
            path = Path(path_info["path"])

            if not path.exists():
                print(f"   ⚠️  Path not found: {path}")
                continue

            print(f"   📁 Searching: {path_info['name']} ({path})")

            # Search this location
            location_results = self._search_directory(path, query_lower, path_info)
            results.extend(location_results)

            print(f"      Found: {len(location_results)} results")

        # Sort by relevance score (descending)
        results.sort(key=lambda x: x.get("relevance_score", 0), reverse=True)

        # Limit results
        results = results[:limit]

        print(f"\n✅ Total results: {len(results)}")
        return results

    def _search_directory(self, directory: Path, query: str, path_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search a single directory for crystals"""
        results = []
        pattern = path_info.get("pattern", "*.*")

        try:
            # Get all matching files
            if pattern.startswith("*."):
                # Simple extension match
                files = list(directory.glob(f"**/{pattern}"))
            else:
                # Pattern with prefix/suffix
                files = list(directory.glob(f"**/{pattern}"))

            for file_path in files:
                # Search file content
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        content_lower = content.lower()

                        # Check if query matches
                        if query in content_lower or query in file_path.name.lower():
                            # Calculate relevance score
                            score = self._calculate_relevance(content_lower, file_path.name.lower(), query)

                            # Extract snippet
                            snippet = self._extract_snippet(content, query, max_length=200)

                            results.append({
                                "file": str(file_path),
                                "filename": file_path.name,
                                "location": path_info["name"],
                                "drive": path_info["path"][0],  # M or G
                                "snippet": snippet,
                                "relevance_score": score,
                                "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                                "size": file_path.stat().st_size
                            })
                except Exception as e:
                    # Skip files that can't be read
                    pass

        except Exception as e:
            print(f"      ❌ Error searching directory: {e}")

        return results

    def _calculate_relevance(self, content: str, filename: str, query: str) -> float:
        """Calculate relevance score for a match"""
        score = 0.0

        # Filename match (high weight)
        if query in filename:
            score += 10.0

        # Content matches (count occurrences)
        content_matches = content.count(query)
        score += min(content_matches * 2.0, 20.0)  # Cap at 20 points

        # Bonus for exact word match
        if re.search(r'\b' + re.escape(query) + r'\b', content):
            score += 5.0

        # Title/header match
        if re.search(r'^#+.*' + re.escape(query), content, re.MULTILINE | re.IGNORECASE):
            score += 8.0

        return score

    def _extract_snippet(self, content: str, query: str, max_length: int = 200) -> str:
        """Extract relevant snippet from content"""
        content_lower = content.lower()
        query_lower = query.lower()

        # Find first occurrence
        index = content_lower.find(query_lower)
        if index == -1:
            # No match in content, return start
            return content[:max_length] + "..."

        # Extract context around match
        start = max(0, index - 50)
        end = min(len(content), index + len(query) + 150)

        snippet = content[start:end]

        # Clean up
        snippet = snippet.strip()
        if start > 0:
            snippet = "..." + snippet
        if end < len(content):
            snippet = snippet + "..."

        return snippet

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about crystal storage"""
        stats = {
            "total_locations": len(self.search_paths),
            "locations": [],
            "total_crystals": 0
        }

        for path_info in self.search_paths:
            path = Path(path_info["path"])

            if path.exists():
                # Count files matching pattern
                pattern = path_info.get("pattern", "*.*")
                files = list(path.glob(f"**/{pattern}"))
                count = len(files)

                stats["locations"].append({
                    "name": path_info["name"],
                    "path": str(path),
                    "drive": path_info["path"][0],
                    "count": count,
                    "accessible": True
                })
                stats["total_crystals"] += count
            else:
                stats["locations"].append({
                    "name": path_info["name"],
                    "path": str(path),
                    "drive": path_info["path"][0],
                    "count": 0,
                    "accessible": False
                })

        return stats


# ==================== MCP INTEGRATION ====================

def cm_search(query: str, drive: str = "ALL", limit: int = 100) -> Dict[str, Any]:
    """
    MCP tool: Search crystals across all locations

    Args:
        query: Search query
        drive: "M", "G", or "ALL"
        limit: Max results

    Returns:
        Search results with metadata
    """
    searcher = CrystalSearchFixed()
    results = searcher.search_crystals(query, drive, limit)

    return {
        "success": True,
        "query": query,
        "drive": drive,
        "count": len(results),
        "results": results
    }


def cm_stats() -> Dict[str, Any]:
    """
    MCP tool: Get crystal storage statistics

    Returns:
        Statistics about all crystal locations
    """
    searcher = CrystalSearchFixed()
    stats = searcher.get_stats()

    return {
        "success": True,
        "stats": stats
    }


# ==================== CLI TESTING ====================

if __name__ == "__main__":
    print("="*70)
    print("💎 CRYSTAL MEMORY HUB - MULTI-PATH SEARCH TEST")
    print("="*70)

    # Initialize
    searcher = CrystalSearchFixed()

    # Get stats
    print("\n📊 STORAGE STATISTICS:")
    print("="*70)
    stats = searcher.get_stats()
    print(f"Total Locations: {stats['total_locations']}")
    print(f"Total Crystals: {stats['total_crystals']}")
    print("\nLocations:")
    for loc in stats['locations']:
        status = "✅" if loc['accessible'] else "❌"
        print(f"  {status} {loc['name']}: {loc['count']} files ({loc['path']})")

    # Test search
    print("\n🔍 TEST SEARCH:")
    print("="*70)
    test_query = "GPU"
    print(f"Query: '{test_query}'")
    results = searcher.search_crystals(test_query, drive="M", limit=10)

    print(f"\nResults ({len(results)}):")
    for i, result in enumerate(results, 1):
        print(f"\n{i}. {result['filename']}")
        print(f"   Location: {result['location']} ({result['drive']}: drive)")
        print(f"   Score: {result['relevance_score']:.1f}")
        print(f"   Snippet: {result['snippet'][:100]}...")

    print("\n" + "="*70)
    print("✅ TEST COMPLETE")
    print("="*70)
