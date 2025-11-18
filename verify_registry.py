#!/usr/bin/env python3
"""Verify expanded registry tool count"""
from PROMETHEUS_CAPABILITY_REGISTRY import PrometheusCapabilityRegistry
from collections import Counter

reg = PrometheusCapabilityRegistry()
caps = reg.get_all_capabilities()

print(f"✅ Total Tools: {len(caps)}")
print("\n📊 By Category:")
cats = Counter([c.category.value for c in caps])
for cat, count in sorted(cats.items()):
    print(f"   {cat}: {count}")

# Show new systems
print("\n🆕 New Systems:")
new_cats = ['autonomous', 'voice', 'memory', 'stealth', 'healing', 'defense']
for cat in new_cats:
    if cat in cats:
        print(f"   ✅ {cat.upper()}: {cats[cat]} tools")
