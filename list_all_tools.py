#!/usr/bin/env python3
"""
PROMETHEUS PRIME - COMPLETE TOOL LIST
Display all 282 MCP tools with categories and descriptions

Authority Level: 11.0
"""

import sys
from pathlib import Path
from collections import defaultdict

# Add project root
sys.path.insert(0, str(Path(__file__).parent))

def main():
    """Generate complete tool list."""
    print("=" * 80)
    print("🔥 PROMETHEUS PRIME - COMPLETE MCP TOOL REGISTRY")
    print("=" * 80)
    print("\nAuthority Level: 11.0")
    print("Total Tools: 282")
    print("Categories: 6")

    try:
        from PROMETHEUS_CAPABILITY_REGISTRY import PrometheusCapabilityRegistry

        registry = PrometheusCapabilityRegistry()
        all_caps = registry.get_all_capabilities()

        print(f"\n✅ Successfully loaded {len(all_caps)} capabilities\n")

        # Group by category
        by_category = defaultdict(list)
        for cap in all_caps:
            by_category[cap.category.value].append(cap)

        # Sort categories by tool count (descending)
        sorted_categories = sorted(by_category.items(), key=lambda x: len(x[1]), reverse=True)

        # Display each category
        for cat_name, caps in sorted_categories:
            cat_display = cat_name.upper().replace('_', ' ')
            print("=" * 80)
            print(f"📦 {cat_display} ({len(caps)} tools)")
            print("=" * 80)

            # Sort tools by name
            caps_sorted = sorted(caps, key=lambda c: c.name)

            for i, cap in enumerate(caps_sorted, 1):
                # Format tool info
                tool_name = cap.mcp_tool_name
                description = cap.description[:70] + "..." if len(cap.description) > 70 else cap.description
                expertise = cap.expertise_level.name
                authority = cap.authority_required

                print(f"\n{i:3d}. {tool_name}")
                print(f"     Description: {description}")
                print(f"     Module: {cap.module_path}")
                print(f"     Class: {cap.class_name}")
                print(f"     Expertise: {expertise} | Authority: {authority}")

                # Show operations if available
                if cap.operations:
                    ops_display = ", ".join(cap.operations[:3])
                    if len(cap.operations) > 3:
                        ops_display += f" (+{len(cap.operations)-3} more)"
                    print(f"     Operations: {ops_display}")

        # Summary statistics
        print("\n" + "=" * 80)
        print("📊 SUMMARY STATISTICS")
        print("=" * 80)

        total_ops = sum(len(cap.operations) for cap in all_caps)
        print(f"\nTotal Capabilities: {len(all_caps)}")
        print(f"Total Operations: {total_ops}")

        print("\nBreakdown by Category:")
        for cat_name, caps in sorted_categories:
            cat_display = cat_name.upper().replace('_', ' ')
            percentage = (len(caps) / len(all_caps)) * 100
            print(f"   • {cat_display:25s}: {len(caps):3d} tools ({percentage:5.1f}%)")

        # Expertise level breakdown
        print("\nBreakdown by Expertise Level:")
        by_expertise = defaultdict(int)
        for cap in all_caps:
            by_expertise[cap.expertise_level.name] += 1

        for level_name, count in sorted(by_expertise.items()):
            percentage = (count / len(all_caps)) * 100
            print(f"   • {level_name:15s}: {count:3d} tools ({percentage:5.1f}%)")

        # Authority level breakdown
        print("\nBreakdown by Authority Required:")
        authority_ranges = {
            '1.0-5.0 (Low)': 0,
            '5.1-8.0 (Medium)': 0,
            '8.1-10.0 (High)': 0,
            '10.1+ (Maximum)': 0
        }

        for cap in all_caps:
            auth = cap.authority_required
            if auth <= 5.0:
                authority_ranges['1.0-5.0 (Low)'] += 1
            elif auth <= 8.0:
                authority_ranges['5.1-8.0 (Medium)'] += 1
            elif auth <= 10.0:
                authority_ranges['8.1-10.0 (High)'] += 1
            else:
                authority_ranges['10.1+ (Maximum)'] += 1

        for range_name, count in authority_ranges.items():
            if count > 0:
                percentage = (count / len(all_caps)) * 100
                print(f"   • {range_name:20s}: {count:3d} tools ({percentage:5.1f}%)")

        print("\n" + "=" * 80)
        print("✅ TOOL LIST GENERATION COMPLETE")
        print("=" * 80)
        print("\n🚀 All tools available via MCP protocol")
        print("📝 Use in Claude Desktop via mcp_server.py")
        print("🔧 Configuration: See .claude/mcp.json\n")

        return 0

    except Exception as e:
        print(f"\n❌ Error loading registry: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
