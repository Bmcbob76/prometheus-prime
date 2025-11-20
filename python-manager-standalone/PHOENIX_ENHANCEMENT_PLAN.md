# Phoenix Healer Enhancement Plan
## Pushing Success Rates to 90%+

**Current Performance vs Target**

| Category | Current | Target | Gain | Strategy |
|----------|---------|--------|------|----------|
| Import Errors | 95% | **99%** | +4% | Package name mapping, fallback strategies |
| Async Errors | 80% | **95%** | +15% | Context-aware fixes, await injection |
| Dependency Conflicts | 70% | **88%** | +18% | Compatibility matrix, multi-version testing |
| I/O Errors | 60% | **85%** | +25% | Permission fixes, template generation |
| Memory Errors | 50% | **75%** | +25% | Auto-chunking, generator conversion |

**Overall Target: 88% success rate** (up from 51%)

---

## 🎯 Enhancement 1: Import Errors (95% → 99%)

### Current Gaps (5%)
- Package name mismatches (cv2 vs opencv-python, PIL vs Pillow)
- Sub-packages not installing (e.g., sklearn.ensemble needs scikit-learn)
- Platform-specific packages (pywin32, curses)
- Deprecated package names (pil vs Pillow)

### Solutions to Add

#### 1.1 Package Name Mapping Database
```python
IMPORT_TO_PACKAGE_MAP = {
    # Common mismatches
    'cv2': 'opencv-python',
    'PIL': 'Pillow',
    'sklearn': 'scikit-learn',
    'yaml': 'pyyaml',
    'Crypto': 'pycryptodome',
    'psycopg2': 'psycopg2-binary',
    'MySQLdb': 'mysqlclient',

    # Sub-package mappings
    'sklearn.ensemble': 'scikit-learn',
    'sklearn.preprocessing': 'scikit-learn',
    'tensorflow.keras': 'tensorflow',
    'torch.nn': 'torch',

    # Platform-specific
    'win32api': 'pywin32',  # Windows only
    'curses': None,  # Built-in on Unix, unavailable on Windows
}
```

#### 1.2 Fallback Installation Strategy
```python
def heal_import_with_fallbacks(module_name):
    # Strategy 1: Try exact name
    if try_install(module_name):
        return True

    # Strategy 2: Try mapping
    if module_name in IMPORT_TO_PACKAGE_MAP:
        if try_install(IMPORT_TO_PACKAGE_MAP[module_name]):
            return True

    # Strategy 3: Try base package (for sub-modules)
    base = module_name.split('.')[0]
    if base != module_name and try_install(base):
        return True

    # Strategy 4: Try common variations
    variations = [
        f'python-{module_name}',
        f'{module_name}2',
        f'{module_name}3',
    ]
    for variant in variations:
        if try_install(variant):
            return True

    # Strategy 5: Search PyPI
    results = search_pypi(module_name)
    if results:
        return try_install(results[0])

    return False
```

**Expected Gain: 95% → 99% (+4%)**

---

## 🎯 Enhancement 2: Async Errors (80% → 95%)

### Current Gaps (20%)
- Coroutine not awaited (forgot `await`)
- sync function in async context
- asyncio.run() in wrong context
- Missing async/await keywords

### Solutions to Add

#### 2.1 Automatic Await Detection & Injection
```python
def inject_await_fixes(script_content, error_text):
    """Detect missing await and auto-inject"""

    # Parse error to find coroutine name
    match = re.search(r"coroutine '(\w+)' was never awaited", error_text)
    if not match:
        return None

    coroutine_name = match.group(1)

    # Find all calls to this coroutine and add await
    pattern = rf'\b{coroutine_name}\('

    # Inject await before the call
    fixed_content = re.sub(
        pattern,
        f'await {coroutine_name}(',
        script_content
    )

    return fixed_content
```

#### 2.2 Context-Aware Async Fixes
```python
def detect_async_context(error_text, script_path):
    """Determine the right fix based on context"""

    # Check if in Jupyter/IPython
    if 'IPython' in sys.modules or 'jupyter' in str(script_path):
        return {
            'fix': 'nest_asyncio',
            'code': 'import nest_asyncio; nest_asyncio.apply()'
        }

    # Check if in thread
    if 'thread' in error_text.lower():
        return {
            'fix': 'create_event_loop',
            'code': 'loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)'
        }

    # Check if using asyncio.run() nested
    with open(script_path) as f:
        content = f.read()
        if 'asyncio.run(' in content and 'async def' in content:
            # Convert asyncio.run() to await
            return {
                'fix': 'convert_to_await',
                'code': '# Replace asyncio.run(coro()) with await coro()'
            }

    return None
```

#### 2.3 Sync-to-Async Converter
```python
def convert_sync_to_async(function_call, error_text):
    """Convert synchronous calls to async equivalents"""

    SYNC_TO_ASYNC_MAP = {
        'requests.get': 'aiohttp.ClientSession().get',
        'requests.post': 'aiohttp.ClientSession().post',
        'time.sleep': 'asyncio.sleep',
        'open(': 'aiofiles.open(',
    }

    # Detect which sync function is being called
    for sync_func, async_func in SYNC_TO_ASYNC_MAP.items():
        if sync_func in function_call:
            return {
                'original': sync_func,
                'replacement': async_func,
                'package_needed': async_func.split('.')[0]
            }

    return None
```

**Expected Gain: 80% → 95% (+15%)**

---

## 🎯 Enhancement 3: Dependency Conflicts (70% → 88%)

### Current Gaps (30%)
- Complex multi-package conflicts
- No known compatible versions
- Conflicting transitive dependencies

### Solutions to Add

#### 3.1 Compatibility Matrix Builder
```python
class CompatibilityMatrix:
    """Learn and store successful dependency combinations"""

    def __init__(self):
        self.matrix = self.load_matrix()

    def record_success(self, package_versions):
        """Record a successful combination"""
        key = self._hash_combination(package_versions)
        self.matrix[key] = {
            'packages': package_versions,
            'python_version': f"{sys.version_info.major}.{sys.version_info.minor}",
            'timestamp': datetime.now().isoformat(),
            'success_count': self.matrix.get(key, {}).get('success_count', 0) + 1
        }
        self.save_matrix()

    def find_compatible_set(self, packages):
        """Find a known-working combination"""
        # Look for combinations that include these packages
        for combo in self.matrix.values():
            if all(pkg in combo['packages'] for pkg in packages):
                return combo['packages']
        return None
```

#### 3.2 Multi-Version Testing
```python
def resolve_conflict_with_testing(conflicting_packages):
    """Try different version combinations"""

    # Get version ranges for each package
    version_options = {}
    for pkg in conflicting_packages:
        versions = get_available_versions(pkg)
        # Get last 5 versions
        version_options[pkg] = versions[-5:]

    # Try combinations (limited to avoid explosion)
    from itertools import product

    for combo in product(*version_options.values()):
        test_env = create_temp_venv()

        try:
            # Install combination
            install_packages(test_env, dict(zip(conflicting_packages, combo)))

            # Test import
            if test_imports(test_env, conflicting_packages):
                return dict(zip(conflicting_packages, combo))
        except:
            continue
        finally:
            cleanup_temp_venv(test_env)

    return None
```

#### 3.3 Known Conflict Patterns Database
```python
KNOWN_CONFLICTS = {
    ('tensorflow', 'numpy'): {
        'tensorflow==2.10.*': 'numpy>=1.19.2,<1.24',
        'tensorflow==2.11.*': 'numpy>=1.21.0,<1.25',
        'tensorflow==2.12.*': 'numpy>=1.22.0,<1.25',
    },
    ('fastapi', 'pydantic'): {
        'fastapi>=0.104': 'pydantic>=2.0',
        'fastapi<0.104': 'pydantic<2.0',
    },
    ('pandas', 'numpy'): {
        'pandas>=1.5': 'numpy>=1.21.0',
        'pandas>=2.0': 'numpy>=1.22.0',
    },
    # Add 50+ more known conflicts
}

def resolve_using_knowledge(pkg1, pkg2):
    """Use known patterns to resolve"""
    conflict_key = tuple(sorted([pkg1, pkg2]))

    if conflict_key in KNOWN_CONFLICTS:
        # Get current versions
        v1 = get_installed_version(pkg1)
        v2 = get_installed_version(pkg2)

        # Find matching rule
        for rule, compatible in KNOWN_CONFLICTS[conflict_key].items():
            if version_matches(v1, rule):
                return compatible

    return None
```

**Expected Gain: 70% → 88% (+18%)**

---

## 🎯 Enhancement 4: I/O Errors (60% → 85%)

### Current Gaps (40%)
- Permission denied (can't auto-fix without sudo)
- File in use by another process
- Invalid file paths
- Encoding issues

### Solutions to Add

#### 4.1 Permission Auto-Fix
```python
def fix_permission_error(file_path, operation):
    """Attempt to fix permission issues"""

    path = Path(file_path)

    # Strategy 1: Try changing permissions
    try:
        if operation == 'read':
            path.chmod(0o644)  # rw-r--r--
        elif operation == 'write':
            path.chmod(0o666)  # rw-rw-rw-
        elif operation == 'execute':
            path.chmod(0o755)  # rwxr-xr-x
        return True
    except PermissionError:
        pass

    # Strategy 2: Try with parent directory
    try:
        path.parent.chmod(0o755)
        return True
    except:
        pass

    # Strategy 3: Suggest sudo/admin
    if sys.platform != 'win32':
        return {
            'manual_fix': True,
            'command': f'sudo chmod +rw {file_path}',
            'message': 'Requires elevated privileges'
        }
    else:
        return {
            'manual_fix': True,
            'message': 'Run as Administrator'
        }
```

#### 4.2 File-in-Use Handler
```python
def handle_file_in_use(file_path):
    """Deal with locked files"""

    import time

    # Strategy 1: Retry with backoff
    for i in range(5):
        try:
            # Try opening
            with open(file_path, 'r') as f:
                return True
        except PermissionError:
            time.sleep(0.5 * (2 ** i))  # Exponential backoff

    # Strategy 2: Try alternative path
    alt_path = file_path + '.tmp'
    try:
        shutil.copy2(file_path, alt_path)
        return alt_path
    except:
        pass

    # Strategy 3: Suggest process termination
    if sys.platform == 'win32':
        # Find process using file
        result = subprocess.run(
            f'handle.exe {file_path}',
            capture_output=True,
            shell=True
        )
        return {
            'blocked_by': result.stdout.decode(),
            'suggestion': 'Close the application using this file'
        }

    return False
```

#### 4.3 Template File Generator
```python
def create_template_file(file_path, file_type):
    """Create template when file is missing"""

    TEMPLATES = {
        '.json': '{}',
        '.yaml': '# Configuration\n',
        '.ini': '[DEFAULT]\n',
        '.env': '# Environment variables\n',
        '.txt': '',
        '.csv': 'column1,column2,column3\n',
        '.md': '# Document\n',
    }

    ext = Path(file_path).suffix

    if ext in TEMPLATES:
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        Path(file_path).write_text(TEMPLATES[ext])
        return True

    return False
```

**Expected Gain: 60% → 85% (+25%)**

---

## 🎯 Enhancement 5: Memory Errors (50% → 75%)

### Current Gaps (50%)
- Out of memory (can't add RAM)
- Large datasets
- Memory leaks

### Solutions to Add

#### 5.1 Automatic Chunking
```python
def inject_chunking(script_content, error_line):
    """Convert full-load to chunked processing"""

    # Detect large file reads
    patterns = [
        (r'pd\.read_csv\([\'"](.+?)[\'"]\)',
         r'pd.read_csv(\1, chunksize=10000)'),

        (r'open\(([^)]+)\)\.read\(\)',
         r'# Process in chunks\nwith open(\1) as f:\n    for chunk in iter(lambda: f.read(4096), ""):\n        process(chunk)'),

        (r'\.readlines\(\)',
         r'# Use generator\nfor line in f:  # Memory efficient\n    process(line)'),
    ]

    for pattern, replacement in patterns:
        if re.search(pattern, script_content):
            return re.sub(pattern, replacement, script_content)

    return None
```

#### 5.2 Generator Conversion
```python
def convert_to_generator(script_content):
    """Convert list comprehensions to generators"""

    # Find large list comprehensions
    pattern = r'\[([^\]]+) for ([^\]]+) in ([^\]]+)\]'

    def replacer(match):
        expr, var, iterable = match.groups()
        # Convert to generator expression
        return f'({expr} for {var} in {iterable})'

    # Only convert if result is used in iteration
    # (not if assigned to variable and accessed multiple times)

    return re.sub(pattern, replacer, script_content)
```

#### 5.3 Memory-Mapped File Usage
```python
def suggest_mmap(file_path, operation):
    """Suggest memory-mapped files for large files"""

    size = Path(file_path).stat().st_size

    # If file > 100MB, suggest mmap
    if size > 100 * 1024 * 1024:
        return {
            'suggestion': 'memory_mapped_file',
            'code': f'''
import mmap

with open('{file_path}', 'r+b') as f:
    mmapped_file = mmap.mmap(f.fileno(), 0)
    # Process memory-mapped file
    # Access like: mmapped_file[0:1000]
'''
        }

    return None
```

#### 5.4 Garbage Collection Forcing
```python
def force_gc_on_memory_error():
    """Aggressively collect garbage"""
    import gc

    # Force collection
    gc.collect(2)  # Full collection

    # Reduce threshold to be more aggressive
    gc.set_threshold(700, 10, 10)

    # Enable debug output
    # gc.set_debug(gc.DEBUG_LEAK)

    return True
```

**Expected Gain: 50% → 75% (+25%)**

---

## 📊 Implementation Priority

### Phase 1: Quick Wins (1-2 days)
1. **Import Name Mapping** (95% → 99%)
   - Add IMPORT_TO_PACKAGE_MAP dictionary
   - Implement fallback strategy
   - **Effort:** Low | **Impact:** High

2. **Permission Auto-Fix** (Part of I/O: 60% → 70%)
   - Auto-chmod when possible
   - **Effort:** Low | **Impact:** Medium

3. **Await Injection** (Part of Async: 80% → 85%)
   - Detect coroutine warnings
   - Inject await keyword
   - **Effort:** Low | **Impact:** Medium

### Phase 2: Medium Complexity (3-5 days)
4. **Context-Aware Async Fixes** (Async: 85% → 92%)
   - Jupyter detection
   - Thread handling
   - **Effort:** Medium | **Impact:** High

5. **Template File Generation** (I/O: 70% → 80%)
   - Common file type templates
   - **Effort:** Low | **Impact:** Medium

6. **Auto-Chunking Injection** (Memory: 50% → 65%)
   - Detect large reads
   - Inject chunking code
   - **Effort:** Medium | **Impact:** High

### Phase 3: Advanced Features (1-2 weeks)
7. **Compatibility Matrix** (Dependency: 70% → 82%)
   - Build learning database
   - Record successful combinations
   - **Effort:** High | **Impact:** High

8. **Multi-Version Testing** (Dependency: 82% → 88%)
   - Temp venv creation
   - Combination testing
   - **Effort:** High | **Impact:** Medium

9. **Generator Conversion** (Memory: 65% → 75%)
   - AST parsing
   - Smart conversion
   - **Effort:** High | **Impact:** Medium

---

## 🎯 Expected Final Results

### After All Enhancements

| Category | Current | Target | Methods Added |
|----------|---------|--------|---------------|
| **Import Errors** | 95% | **99%** | Name mapping, fallbacks, PyPI search |
| **Async Errors** | 80% | **95%** | Context detection, await injection, sync conversion |
| **Dependency Conflicts** | 70% | **88%** | Compatibility matrix, multi-version testing |
| **I/O Errors** | 60% | **85%** | Permission fix, retry, templates |
| **Memory Errors** | 50% | **75%** | Auto-chunking, generators, mmap, GC |

### Overall Success Rate
- **Current:** 51%
- **Target:** **88%**
- **Gain:** +37 percentage points
- **Automatic fixes:** Nearly 9 out of 10 errors

---

## 💡 Bonus Enhancements

### Beyond 90%

10. **AI-Powered Error Analysis**
    - Use LLM to analyze complex errors
    - Generate custom fixes
    - Learn from StackOverflow solutions
    - **Potential:** 88% → 93%

11. **Predictive Healing**
    - Detect potential errors before execution
    - Pre-install likely dependencies
    - Pre-create likely files
    - **Potential:** 93% → 95%

12. **Cloud-Assisted Resolution**
    - Query central database of fixes
    - Share successful resolutions
    - Community-driven solutions
    - **Potential:** 95% → 97%

---

## 📈 ROI Analysis

### Development Time vs Benefit

| Enhancement | Dev Time | Success Gain | ROI |
|-------------|----------|--------------|-----|
| Import Mapping | 2 hours | +4% | ⭐⭐⭐⭐⭐ |
| Await Injection | 4 hours | +5% | ⭐⭐⭐⭐⭐ |
| Permission Fix | 3 hours | +10% | ⭐⭐⭐⭐⭐ |
| Chunking | 8 hours | +15% | ⭐⭐⭐⭐ |
| Context-Aware Async | 12 hours | +10% | ⭐⭐⭐⭐ |
| Compatibility Matrix | 24 hours | +12% | ⭐⭐⭐ |
| Multi-Version Testing | 32 hours | +6% | ⭐⭐ |

**Recommended Focus:** Phase 1 + Phase 2 (1 week) for 70% overall success rate

---

Would you like me to implement any of these enhancements? I'd recommend starting with Phase 1 (quick wins) to get the most impact with least effort.
