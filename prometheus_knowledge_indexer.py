"""
PROMETHEUS PRIME KNOWLEDGE INDEXER - REAL IMPLEMENTATION
Indexes 50,882+ files for searchable knowledge base
Extracts techniques, patterns, and categorizes content
NO PLACEHOLDERS - Actually processes files and builds index
"""

import os
import json
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict
from datetime import datetime

class PrometheusKnowledgeIndexer:
    """REAL knowledge indexer for Prometheus Prime repository"""
    
    def __init__(self):
        self.base_path = Path("P:/ECHO_PRIME/prometheus_prime")
        self.index_path = self.base_path / "KNOWLEDGE_INDEX"
        self.index_path.mkdir(exist_ok=True)
        
        # Statistics
        self.stats = {
            'total_files': 0,
            'indexed_files': 0,
            'skipped_files': 0,
            'total_size_bytes': 0,
            'categories': defaultdict(int),
            'languages': defaultdict(int),
            'techniques_found': 0
        }
        
        # Index structures
        self.file_index = {}  # filename -> metadata
        self.technique_index = defaultdict(list)  # technique -> [files]
        self.category_index = defaultdict(list)  # category -> [files]
        self.language_index = defaultdict(list)  # language -> [files]
        self.content_hashes = set()  # deduplicate identical content
    
    def get_file_language(self, filepath: Path) -> str:
        """Determine programming language from extension"""
        ext = filepath.suffix.lower()
        language_map = {
            '.py': 'Python',
            '.c': 'C',
            '.cpp': 'C++',
            '.h': 'C/C++ Header',
            '.rb': 'Ruby',
            '.pl': 'Perl',
            '.pm': 'Perl Module',
            '.php': 'PHP',
            '.js': 'JavaScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.sh': 'Shell',
            '.bash': 'Bash',
            '.html': 'HTML',
            '.css': 'CSS',
            '.sql': 'SQL',
            '.txt': 'Text',
            '.md': 'Markdown',
            '.json': 'JSON',
            '.xml': 'XML',
            '.yml': 'YAML',
            '.yaml': 'YAML'
        }
        return language_map.get(ext, f'Unknown{ext}')
    
    def categorize_file(self, filepath: Path, content: str) -> List[str]:
        """Categorize file based on path and content"""
        categories = []
        path_str = str(filepath).lower()
        content_lower = content.lower()
        
        # Path-based categories
        category_patterns = {
            'networking': ['network', 'socket', 'tcp', 'udp', 'http', 'protocol'],
            'security': ['security', 'crypto', 'encrypt', 'auth', 'password', 'hash'],
            'database': ['database', 'sql', 'mysql', 'postgres', 'sqlite', 'db'],
            'web': ['web', 'html', 'css', 'javascript', 'http', 'server'],
            'ai_ml': ['ai', 'ml', 'neural', 'machine_learning', 'tensorflow', 'pytorch'],
            'system': ['system', 'kernel', 'process', 'thread', 'memory', 'cpu'],
            'file_ops': ['file', 'directory', 'io', 'read', 'write', 'stream'],
            'api': ['api', 'rest', 'graphql', 'endpoint', 'service'],
            'testing': ['test', 'unit', 'integration', 'mock', 'assert'],
            'automation': ['auto', 'script', 'batch', 'cron', 'scheduler'],
            'data_processing': ['data', 'parse', 'transform', 'etl', 'pipeline'],
            'visualization': ['visual', 'graph', 'chart', 'plot', 'display'],
            'exploit': ['exploit', 'vulnerability', 'overflow', 'injection', 'xss'],
            'forensics': ['forensic', 'analysis', 'dump', 'memory', 'artifact'],
            'reverse_engineering': ['reverse', 'disasm', 'decompile', 'binary'],
            'penetration_testing': ['pentest', 'scan', 'probe', 'audit', 'assess']
        }
        
        for category, patterns in category_patterns.items():
            if any(pattern in path_str or pattern in content_lower for pattern in patterns):
                categories.append(category)
        
        return categories if categories else ['general']
    
    def extract_techniques(self, filepath: Path, content: str, language: str) -> List[str]:
        """Extract programming techniques and patterns from file"""
        techniques = []
        
        # Common technique patterns across languages
        technique_patterns = {
            'socket_programming': [r'socket\s*\(', r'bind\s*\(', r'listen\s*\(', r'accept\s*\('],
            'file_io': [r'open\s*\(', r'fopen', r'read\s*\(', r'write\s*\(', r'File\.open'],
            'threading': [r'Thread', r'pthread', r'threading', r'concurrent'],
            'async_programming': [r'async\s+def', r'await\s+', r'Promise', r'Future'],
            'regex': [r're\.compile', r'regex', r'pattern\.match', r'/.*?/'],
            'encryption': [r'encrypt', r'decrypt', r'cipher', r'AES', r'RSA'],
            'hashing': [r'md5', r'sha', r'hash', r'digest'],
            'sql_injection': [r'sql.*injection', r'UNION\s+SELECT', r'OR\s+1=1'],
            'xss': [r'<script', r'javascript:', r'onerror=', r'onload='],
            'buffer_overflow': [r'strcpy', r'gets\s*\(', r'sprintf', r'strcat'],
            'api_calls': [r'requests\.', r'urllib', r'http\.get', r'fetch\('],
            'serialization': [r'pickle', r'json\.', r'marshal', r'serialize'],
            'compression': [r'gzip', r'zip', r'compress', r'deflate'],
            'parsing': [r'parse', r'parser', r'ast\.', r'BeautifulSoup'],
            'subprocess': [r'subprocess', r'popen', r'system\s*\(', r'exec\s*\('],
            'network_scanning': [r'nmap', r'scan', r'port.*scan', r'ping'],
            'packet_sniffing': [r'pcap', r'sniff', r'packet', r'capture'],
            'web_scraping': [r'scrape', r'crawler', r'spider', r'BeautifulSoup'],
            'brute_force': [r'brute.*force', r'password.*crack', r'dictionary.*attack'],
            'privilege_escalation': [r'privilege', r'escalat', r'sudo', r'root']
        }
        
        for technique, patterns in technique_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    techniques.append(technique)
                    break
        
        return list(set(techniques))  # Remove duplicates
    
    def index_file(self, filepath: Path) -> Optional[Dict]:
        """Index a single file"""
        try:
            # Skip binary files and very large files
            if filepath.suffix.lower() in ['.exe', '.dll', '.so', '.dylib', '.bin', '.pyc']:
                self.stats['skipped_files'] += 1
                return None
            
            file_size = filepath.stat().st_size
            if file_size > 1_000_000:  # Skip files > 1MB
                self.stats['skipped_files'] += 1
                return None
            
            # Read file content
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(100_000)  # Read first 100KB
            except Exception:
                self.stats['skipped_files'] += 1
                return None
            
            # Check for duplicate content
            content_hash = hashlib.md5(content.encode()).hexdigest()
            if content_hash in self.content_hashes:
                self.stats['skipped_files'] += 1
                return None
            self.content_hashes.add(content_hash)
            
            # Extract metadata
            language = self.get_file_language(filepath)
            categories = self.categorize_file(filepath, content)
            techniques = self.extract_techniques(filepath, content, language)
            
            # Create index entry
            relative_path = filepath.relative_to(self.base_path)
            index_entry = {
                'path': str(relative_path),
                'filename': filepath.name,
                'size': file_size,
                'language': language,
                'categories': categories,
                'techniques': techniques,
                'hash': content_hash,
                'indexed_at': datetime.now().isoformat()
            }
            
            # Update indexes
            self.file_index[str(relative_path)] = index_entry
            
            for category in categories:
                self.category_index[category].append(str(relative_path))
                self.stats['categories'][category] += 1
            
            self.language_index[language].append(str(relative_path))
            self.stats['languages'][language] += 1
            
            for technique in techniques:
                self.technique_index[technique].append(str(relative_path))
                self.stats['techniques_found'] += 1
            
            self.stats['indexed_files'] += 1
            self.stats['total_size_bytes'] += file_size
            
            return index_entry
            
        except Exception as e:
            self.stats['skipped_files'] += 1
            return None
    
    def build_index(self, max_files: Optional[int] = None) -> Dict:
        """Build complete index of Prometheus repository"""
        print("\n" + "="*70)
        print("🔥 PROMETHEUS PRIME KNOWLEDGE INDEXER")
        print("="*70)
        print(f"Repository: {self.base_path}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        
        # Get all files
        all_files = list(self.base_path.rglob("*"))
        file_list = [f for f in all_files if f.is_file() and f.name != 'prometheus_knowledge_indexer.py']
        
        if max_files:
            file_list = file_list[:max_files]
        
        self.stats['total_files'] = len(file_list)
        print(f"\n📊 Found {self.stats['total_files']} files to process")
        print("Processing...")
        
        # Index files with progress
        for i, filepath in enumerate(file_list, 1):
            if i % 1000 == 0:
                print(f"   Processed {i:,}/{self.stats['total_files']:,} files ({i/self.stats['total_files']*100:.1f}%)")
            
            self.index_file(filepath)
        
        print(f"\n✅ Indexing complete!")
        
        # Save indexes
        self.save_indexes()
        
        # Print summary
        self.print_summary()
        
        return self.stats
    
    def save_indexes(self):
        """Save all indexes to JSON files"""
        print(f"\n💾 Saving indexes...")
        
        indexes = {
            'file_index.json': self.file_index,
            'technique_index.json': dict(self.technique_index),
            'category_index.json': dict(self.category_index),
            'language_index.json': dict(self.language_index),
            'stats.json': dict(self.stats)
        }
        
        for filename, data in indexes.items():
            filepath = self.index_path / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            print(f"   ✅ {filename}")
        
        print(f"\n📄 Indexes saved to: {self.index_path}")
    
    def print_summary(self):
        """Print indexing summary"""
        print("\n" + "="*70)
        print("📊 INDEXING SUMMARY")
        print("="*70)
        print(f"Total Files Found: {self.stats['total_files']:,}")
        print(f"Successfully Indexed: {self.stats['indexed_files']:,}")
        print(f"Skipped (duplicates/binary): {self.stats['skipped_files']:,}")
        print(f"Total Size: {self.stats['total_size_bytes'] / 1_000_000:.2f} MB")
        print(f"Unique Techniques: {len(self.technique_index)}")
        print(f"Total Technique Instances: {self.stats['techniques_found']}")
        
        print("\n📚 TOP LANGUAGES:")
        top_languages = sorted(self.stats['languages'].items(), key=lambda x: x[1], reverse=True)[:10]
        for lang, count in top_languages:
            print(f"   {lang}: {count:,} files")
        
        print("\n📂 TOP CATEGORIES:")
        top_categories = sorted(self.stats['categories'].items(), key=lambda x: x[1], reverse=True)[:10]
        for cat, count in top_categories:
            print(f"   {cat}: {count:,} files")
        
        print("\n🔧 TOP TECHNIQUES:")
        top_techniques = sorted(
            [(k, len(v)) for k, v in self.technique_index.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        for tech, count in top_techniques:
            print(f"   {tech}: {count:,} files")
        
        print("="*70)
    
    def search_techniques(self, query: str) -> List[Dict]:
        """Search for files by technique"""
        query_lower = query.lower()
        results = []
        
        for technique, files in self.technique_index.items():
            if query_lower in technique.lower():
                for filepath in files[:10]:  # Limit results
                    if filepath in self.file_index:
                        results.append(self.file_index[filepath])
        
        return results
    
    def search_category(self, category: str) -> List[Dict]:
        """Search for files by category"""
        if category in self.category_index:
            return [self.file_index[f] for f in self.category_index[category][:100]]
        return []
    
    def search_language(self, language: str) -> List[Dict]:
        """Search for files by language"""
        if language in self.language_index:
            return [self.file_index[f] for f in self.language_index[language][:100]]
        return []

def main():
    """Run Prometheus Knowledge Indexer"""
    indexer = PrometheusKnowledgeIndexer()
    
    # Index first 10,000 files for testing (full index would be all 50,882)
    # Set to None for complete indexing
    indexer.build_index(max_files=10000)
    
    print("\n" + "="*70)
    print("✅ PROMETHEUS PRIME KNOWLEDGE INDEX COMPLETE")
    print("="*70)
    print("\nIndex is now searchable by:")
    print("  • Techniques (socket_programming, encryption, api_calls, etc.)")
    print("  • Categories (networking, security, web, ai_ml, etc.)")
    print("  • Languages (Python, C, Ruby, Perl, etc.)")
    print("\nExample searches:")
    print('  indexer.search_techniques("socket")')
    print('  indexer.search_category("security")')
    print('  indexer.search_language("Python")')
    print("="*70)
    
    return indexer

if __name__ == "__main__":
    indexer = main()
