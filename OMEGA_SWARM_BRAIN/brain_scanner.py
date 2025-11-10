#!/usr/bin/env python3
"""
MASTER BRAIN SCANNER - X1200 SOVEREIGN AI
Commander Bobby Don McWilliams II - Authority Level 11.0
Scans all drives for brain modules and compiles unified registry
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Set
from datetime import datetime
from collections import defaultdict

class BrainScanner:
    """Scans all drives for AI brain modules"""
    
    def __init__(self):
        self.brain_registry = {
            'scan_time': datetime.now().isoformat(),
            'commander': 'Bobby Don McWilliams II',
            'authority_level': 11.0,
            'drives_scanned': [],
            'total_brains_found': 0,
            'categories': {
                'trinity_brains': [],
                'swarm_brains': [],
                'guild_brains': [],
                'agent_brains': [],
                'consciousness_modules': [],
                'personality_brains': [],
                'diagnostic_brains': [],
                'memory_brains': [],
                'orchestrator_brains': [],
                'other_brains': []
            },
            'stats': {}
        }
        
        self.brain_patterns = [
            '*brain*.py', '*trinity*.py', '*swarm*.py', '*guild*.py',
            '*consciousness*.py', '*personality*.py', '*agent*.py',
            '*orchestrat*.py', '*memory*.py', '*mind*.py'
        ]
        
    def scan_drive(self, drive_letter: str) -> int:
        """Scan a drive for brain modules"""
        drive_path = Path(f"{drive_letter}:/")
        
        if not drive_path.exists():
            print(f"⚠️ Drive {drive_letter}: not accessible")
            return 0
        
        print(f"\n🔍 Scanning {drive_letter}: drive...")
        self.brain_registry['drives_scanned'].append(drive_letter)
        
        found_count = 0
        
        for pattern in self.brain_patterns:
            try:
                for filepath in drive_path.rglob(pattern):
                    if filepath.is_file() and filepath.suffix == '.py':
                        brain_info = self._analyze_brain_module(filepath)
                        if brain_info:
                            self._categorize_brain(brain_info)
                            found_count += 1
                            
                            if found_count % 10 == 0:
                                print(f"   Found {found_count} brain modules...", end='\r')
            except Exception as e:
                # Skip permission errors
                pass
        
        print(f"✅ Drive {drive_letter}: found {found_count} brain modules")
        return found_count
    
    def _analyze_brain_module(self, filepath: Path) -> Dict:
        """Analyze a brain module file"""
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            
            # Calculate hash
            file_hash = hashlib.md5(content.encode()).hexdigest()
            
            # Get basic info
            stats = filepath.stat()
            
            brain_info = {
                'path': str(filepath),
                'name': filepath.name,
                'size': stats.st_size,
                'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'hash': file_hash,
                'lines': len(content.splitlines()),
                'imports': self._extract_imports(content),
                'classes': self._extract_classes(content),
                'functions': self._extract_functions(content),
                'keywords': self._extract_keywords(content)
            }
            
            return brain_info
            
        except Exception as e:
            return None
    
    def _extract_imports(self, content: str) -> List[str]:
        """Extract import statements"""
        imports = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                imports.append(line)
        return imports[:10]  # Limit to first 10
    
    def _extract_classes(self, content: str) -> List[str]:
        """Extract class names"""
        classes = []
        for line in content.splitlines():
            if line.strip().startswith('class '):
                class_name = line.split('class ')[1].split('(')[0].split(':')[0].strip()
                classes.append(class_name)
        return classes
    
    def _extract_functions(self, content: str) -> List[str]:
        """Extract function names"""
        functions = []
        for line in content.splitlines():
            if line.strip().startswith('def '):
                func_name = line.split('def ')[1].split('(')[0].strip()
                if not func_name.startswith('_'):  # Skip private functions
                    functions.append(func_name)
        return functions[:20]  # Limit to first 20
    
    def _extract_keywords(self, content: str) -> List[str]:
        """Extract relevant keywords"""
        keywords = []
        keyword_patterns = [
            'trinity', 'sage', 'thorne', 'nyx', 'swarm', 'guild',
            'consciousness', 'agent', 'orchestrat', 'memory', 'brain',
            'decision', 'consensus', 'harmony', 'authority'
        ]
        
        content_lower = content.lower()
        for keyword in keyword_patterns:
            if keyword in content_lower:
                keywords.append(keyword)
        
        return list(set(keywords))
    
    def _categorize_brain(self, brain_info: Dict):
        """Categorize brain module by type"""
        name_lower = brain_info['name'].lower()
        keywords = brain_info['keywords']
        
        if 'trinity' in name_lower or 'sage' in keywords or 'thorne' in keywords or 'nyx' in keywords:
            self.brain_registry['categories']['trinity_brains'].append(brain_info)
        elif 'swarm' in name_lower or 'swarm' in keywords:
            self.brain_registry['categories']['swarm_brains'].append(brain_info)
        elif 'guild' in name_lower or 'guild' in keywords:
            self.brain_registry['categories']['guild_brains'].append(brain_info)
        elif 'personality' in name_lower or 'agent' in keywords:
            self.brain_registry['categories']['agent_brains'].append(brain_info)
        elif 'consciousness' in name_lower or 'consciousness' in keywords:
            self.brain_registry['categories']['consciousness_modules'].append(brain_info)
        elif 'personality' in name_lower:
            self.brain_registry['categories']['personality_brains'].append(brain_info)
        elif 'gs343' in name_lower or 'diagnostic' in name_lower:
            self.brain_registry['categories']['diagnostic_brains'].append(brain_info)
        elif 'memory' in name_lower or 'memory' in keywords:
            self.brain_registry['categories']['memory_brains'].append(brain_info)
        elif 'orchestrat' in name_lower or 'orchestrat' in keywords:
            self.brain_registry['categories']['orchestrator_brains'].append(brain_info)
        else:
            self.brain_registry['categories']['other_brains'].append(brain_info)
        
        self.brain_registry['total_brains_found'] += 1
    
    def scan_all_drives(self):
        """Scan all specified drives"""
        drives_to_scan = ['P', 'E', 'B', 'X', 'M']
        
        print(f"\n{'='*80}")
        print(f"🧠 MASTER BRAIN SCANNER - X1200 SOVEREIGN AI")
        print(f"{'='*80}")
        print(f"👤 Commander: Bobby Don McWilliams II")
        print(f"🎖️ Authority Level: 11.0")
        print(f"📂 Drives to scan: {', '.join(drives_to_scan)}")
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}\n")
        
        for drive in drives_to_scan:
            self.scan_drive(drive)
        
        self._calculate_stats()
        self._print_summary()
        self._save_registry()
    
    def _calculate_stats(self):
        """Calculate statistics"""
        self.brain_registry['stats'] = {
            'total_files': self.brain_registry['total_brains_found'],
            'total_lines': sum(b['lines'] for cat in self.brain_registry['categories'].values() for b in cat),
            'total_size_mb': sum(b['size'] for cat in self.brain_registry['categories'].values() for b in cat) / (1024 * 1024),
            'trinity_count': len(self.brain_registry['categories']['trinity_brains']),
            'swarm_count': len(self.brain_registry['categories']['swarm_brains']),
            'guild_count': len(self.brain_registry['categories']['guild_brains']),
            'agent_count': len(self.brain_registry['categories']['agent_brains']),
            'consciousness_count': len(self.brain_registry['categories']['consciousness_modules']),
            'personality_count': len(self.brain_registry['categories']['personality_brains']),
            'diagnostic_count': len(self.brain_registry['categories']['diagnostic_brains']),
            'memory_count': len(self.brain_registry['categories']['memory_brains']),
            'orchestrator_count': len(self.brain_registry['categories']['orchestrator_brains']),
            'other_count': len(self.brain_registry['categories']['other_brains'])
        }
    
    def _print_summary(self):
        """Print scan summary"""
        stats = self.brain_registry['stats']
        
        print(f"\n{'='*80}")
        print(f"📊 SCAN RESULTS")
        print(f"{'='*80}\n")
        
        print(f"🎯 Total Brain Modules Found: {stats['total_files']:,}")
        print(f"📝 Total Lines of Code: {stats['total_lines']:,}")
        print(f"💾 Total Size: {stats['total_size_mb']:.2f} MB")
        print(f"📂 Drives Scanned: {', '.join(self.brain_registry['drives_scanned'])}")
        
        print(f"\n{'='*80}")
        print(f"📦 BRAIN CATEGORIES")
        print(f"{'='*80}\n")
        
        print(f"🔱 Trinity Brains: {stats['trinity_count']}")
        print(f"🐝 Swarm Brains: {stats['swarm_count']}")
        print(f"⚔️ Guild Brains: {stats['guild_count']}")
        print(f"🤖 Agent Brains: {stats['agent_count']}")
        print(f"🧘 Consciousness Modules: {stats['consciousness_count']}")
        print(f"👤 Personality Brains: {stats['personality_count']}")
        print(f"🔧 Diagnostic Brains: {stats['diagnostic_count']}")
        print(f"💭 Memory Brains: {stats['memory_count']}")
        print(f"🎼 Orchestrator Brains: {stats['orchestrator_count']}")
        print(f"📋 Other Brains: {stats['other_count']}")
        
        print(f"\n{'='*80}\n")
    
    def _save_registry(self):
        """Save brain registry to file"""
        output_path = Path("P:/ECHO_PRIME/MASTER_BRAIN/brain_registry.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.brain_registry, f, indent=2)
        
        print(f"💾 Registry saved to: {output_path}")
        
        # Also save summary
        summary_path = Path("P:/ECHO_PRIME/MASTER_BRAIN/brain_registry_summary.txt")
        with open(summary_path, 'w') as f:
            f.write("="*80 + "\n")
            f.write("MASTER BRAIN REGISTRY - X1200 SOVEREIGN AI\n")
            f.write("="*80 + "\n\n")
            f.write(f"Commander: Bobby Don McWilliams II\n")
            f.write(f"Authority Level: 11.0\n")
            f.write(f"Scan Time: {self.brain_registry['scan_time']}\n\n")
            f.write(f"Total Brain Modules: {self.brain_registry['stats']['total_files']:,}\n")
            f.write(f"Total Lines: {self.brain_registry['stats']['total_lines']:,}\n")
            f.write(f"Total Size: {self.brain_registry['stats']['total_size_mb']:.2f} MB\n\n")
            f.write("="*80 + "\n")
            f.write("CATEGORIES\n")
            f.write("="*80 + "\n\n")
            for category, count_key in [
                ('Trinity Brains', 'trinity_count'),
                ('Swarm Brains', 'swarm_count'),
                ('Guild Brains', 'guild_count'),
                ('Agent Brains', 'agent_count'),
                ('Consciousness Modules', 'consciousness_count'),
                ('Personality Brains', 'personality_count'),
                ('Diagnostic Brains', 'diagnostic_count'),
                ('Memory Brains', 'memory_count'),
                ('Orchestrator Brains', 'orchestrator_count'),
                ('Other Brains', 'other_count')
            ]:
                f.write(f"{category}: {self.brain_registry['stats'][count_key]}\n")
        
        print(f"📄 Summary saved to: {summary_path}")
        
        return output_path


if __name__ == '__main__':
    scanner = BrainScanner()
    scanner.scan_all_drives()
    
    print(f"\n✅ Master Brain scan complete!")
    print(f"🎯 Ready to build unified orchestrator")
