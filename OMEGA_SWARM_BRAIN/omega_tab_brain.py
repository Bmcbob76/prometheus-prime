"""
🧠 OMEGA TAB BRAIN - Advanced Tab Management & Loading System
Commander Bobby Don McWilliams II - GUI Tab Orchestration
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib

@dataclass
class TabConfig:
    name: str
    path: str
    lazy_load: bool
    preload: bool
    cache_ttl: int  # seconds
    dependencies: List[str]
    memory_limit_mb: int

class OmegaTabBrain:
    """Advanced tab management and optimization system"""
    
    def __init__(self):
        self.tab_configs: Dict[str, TabConfig] = {}
        self.tab_cache: Dict[str, str] = {}
        self.load_order: List[str] = []
        
        # Base path for tabs
        self.tabs_base = Path("P:/ECHO_PRIME/ECHO PRIMEGUI/electron-app/TABS")
        
        self._initialize_default_tabs()
        
        print("🧠 OMEGA TAB BRAIN INITIALIZED")
    
    def _initialize_default_tabs(self):
        """Initialize default tab configurations"""
        default_tabs = [
            ('AI_CHAT', True, False, 3600, [], 100),
            ('NEURAL_NETWORK', True, True, 7200, ['THREE_JS'], 200),
            ('SERVER_STATUS', False, True, 300, [], 50),
            ('AUTHENTICATION', False, True, 1800, [], 30),
            ('CRYSTAL_MEMORY', True, False, 3600, [], 150)
        ]
        
        for name, lazy, preload, ttl, deps, mem in default_tabs:
            self.register_tab(name, lazy, preload, ttl, deps, mem)
    
    def register_tab(self, name: str, lazy_load: bool = True, preload: bool = False,
                    cache_ttl: int = 3600, dependencies: List[str] = None, 
                    memory_limit_mb: int = 100):
        """Register a new tab configuration"""
        tab_path = self.tabs_base / name / "index.html"
        
        config = TabConfig(
            name=name,
            path=str(tab_path),
            lazy_load=lazy_load,
            preload=preload,
            cache_ttl=cache_ttl,
            dependencies=dependencies or [],
            memory_limit_mb=memory_limit_mb
        )
        
        self.tab_configs[name] = config
        print(f"✅ Registered tab: {name}")
    
    def get_load_order(self) -> List[str]:
        """Calculate optimal tab loading order based on dependencies"""
        loaded = set()
        order = []
        
        def load_tab(tab_name: str):
            if tab_name in loaded:
                return
            
            config = self.tab_configs.get(tab_name)
            if not config:
                return
            
            # Load dependencies first
            for dep in config.dependencies:
                load_tab(dep)
            
            order.append(tab_name)
            loaded.add(tab_name)
        
        # Preload tabs first
        for name, config in self.tab_configs.items():
            if config.preload:
                load_tab(name)
        
        # Then lazy-load tabs
        for name, config in self.tab_configs.items():
            if config.lazy_load and name not in loaded:
                load_tab(name)
        
        self.load_order = order
        return order
    
    def get_tab_content(self, tab_name: str) -> Optional[str]:
        """Get tab content with caching"""
        # Check cache first
        cache_key = self._get_cache_key(tab_name)
        if cache_key in self.tab_cache:
            print(f"📦 Retrieved {tab_name} from cache")
            return self.tab_cache[cache_key]
        
        # Load from file
        config = self.tab_configs.get(tab_name)
        if not config:
            print(f"❌ Tab not found: {tab_name}")
            return None
        
        try:
            with open(config.path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Cache content
            self.tab_cache[cache_key] = content
            print(f"✅ Loaded and cached: {tab_name}")
            return content
            
        except FileNotFoundError:
            print(f"❌ Tab file not found: {config.path}")
            return None
    
    def _get_cache_key(self, tab_name: str) -> str:
        """Generate cache key for tab"""
        config = self.tab_configs.get(tab_name)
        if not config:
            return tab_name
        
        # Include file modification time in cache key
        try:
            mtime = Path(config.path).stat().st_mtime
            key_data = f"{tab_name}:{mtime}"
            return hashlib.md5(key_data.encode()).hexdigest()
        except:
            return tab_name
    
    def clear_cache(self, tab_name: str = None):
        """Clear tab cache"""
        if tab_name:
            cache_key = self._get_cache_key(tab_name)
            if cache_key in self.tab_cache:
                del self.tab_cache[cache_key]
                print(f"🧹 Cleared cache for: {tab_name}")
        else:
            self.tab_cache.clear()
            print("🧹 Cleared all tab cache")
    
    def get_memory_usage(self) -> Dict:
        """Get current tab memory usage"""
        total_cache_size = sum(len(content) for content in self.tab_cache.values())
        
        return {
            'cached_tabs': len(self.tab_cache),
            'cache_size_kb': total_cache_size / 1024,
            'cache_size_mb': total_cache_size / (1024 * 1024),
            'tabs': {
                name: {
                    'cached': self._get_cache_key(name) in self.tab_cache,
                    'limit_mb': config.memory_limit_mb
                }
                for name, config in self.tab_configs.items()
            }
        }
    
    def export_config_for_js(self) -> str:
        """Export tab configuration for JavaScript"""
        config = {
            'tabs': {
                name: {
                    'path': f"/Tabs/{name}/index.html",
                    'lazyLoad': cfg.lazy_load,
                    'preload': cfg.preload,
                    'cacheTTL': cfg.cache_ttl,
                    'dependencies': cfg.dependencies,
                    'memoryLimit': cfg.memory_limit_mb
                }
                for name, cfg in self.tab_configs.items()
            },
            'loadOrder': self.get_load_order()
        }
        
        js_content = f"""// 🧠 TAB MANAGEMENT CONFIG - Generated by OMEGA TAB BRAIN
const TAB_CONFIG = {json.dumps(config, indent=2)};

// Tab loader with caching
async function loadTabContent(tabName) {{
    const config = TAB_CONFIG.tabs[tabName];
    if (!config) {{
        console.error('Tab not found:', tabName);
        return null;
    }}
    
    // Check cache
    const cacheKey = `tab_${{tabName}}`;
    const cached = localStorage.getItem(cacheKey);
    if (cached) {{
        const {{content, timestamp}} = JSON.parse(cached);
        if (Date.now() - timestamp < config.cacheTTL * 1000) {{
            console.log('📦 Retrieved from cache:', tabName);
            return content;
        }}
    }}
    
    // Load from server
    try {{
        const response = await fetch(config.path);
        const content = await response.text();
        
        // Cache content
        localStorage.setItem(cacheKey, JSON.stringify({{
            content: content,
            timestamp: Date.now()
        }}));
        
        console.log('✅ Loaded and cached:', tabName);
        return content;
    }} catch (error) {{
        console.error('❌ Failed to load tab:', tabName, error);
        return null;
    }}
}}

if (typeof module !== 'undefined' && module.exports) {{
    module.exports = {{ TAB_CONFIG, loadTabContent }};
}}
"""
        
        return js_content


# CLI Interface
if __name__ == '__main__':
    import sys
    
    brain = OmegaTabBrain()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'order':
            order = brain.get_load_order()
            print("Tab Load Order:")
            for i, tab in enumerate(order, 1):
                print(f"  {i}. {tab}")
        
        elif sys.argv[1] == 'memory':
            usage = brain.get_memory_usage()
            print(json.dumps(usage, indent=2))
        
        elif sys.argv[1] == 'export':
            js_code = brain.export_config_for_js()
            output = Path("P:/ECHO_PRIME/ECHO PRIMEGUI/electron-app/tab-config.js")
            output.write_text(js_code)
            print(f"✅ Exported to: {output}")
        
        else:
            print("Usage: python omega_tab_brain.py [order|memory|export]")
    else:
        print(f"Registered tabs: {len(brain.tab_configs)}")
        for name in brain.tab_configs:
            print(f"  - {name}")
