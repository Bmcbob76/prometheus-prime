#!/usr/bin/env python3
"""
PyManager Plugin System - Extensibility Framework
Load and execute custom plugins for extending PyManager functionality
"""

import sys
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from abc import ABC, abstractmethod


class PluginHook:
    """Plugin hook points in PyManager lifecycle"""

    PRE_VERSION_DETECTION = 'pre_version_detection'
    POST_VERSION_DETECTION = 'post_version_detection'
    PRE_EXECUTION = 'pre_execution'
    POST_EXECUTION = 'post_execution'
    PRE_AUTO_FIX = 'pre_auto_fix'
    POST_AUTO_FIX = 'post_auto_fix'
    ON_ERROR = 'on_error'


class Plugin(ABC):
    """Base class for PyManager plugins"""

    def __init__(self, config: Dict):
        self.config = config
        self.enabled = True

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass

    @property
    def description(self) -> str:
        """Plugin description"""
        return "No description provided"

    @property
    def hooks(self) -> List[str]:
        """List of hooks this plugin subscribes to"""
        return []

    def on_pre_version_detection(self, script_path: Path, context: Dict) -> Optional[str]:
        """
        Called before version detection

        Returns:
            Version to use (overrides detection) or None
        """
        return None

    def on_post_version_detection(self, script_path: Path, detected_version: str, context: Dict) -> Optional[str]:
        """
        Called after version detection

        Returns:
            Modified version or None (keep detected version)
        """
        return None

    def on_pre_execution(self, script_path: Path, python_version: str, context: Dict) -> bool:
        """
        Called before script execution

        Returns:
            True to continue execution, False to cancel
        """
        return True

    def on_post_execution(self, script_path: Path, exit_code: int, context: Dict):
        """Called after script execution"""
        pass

    def on_pre_auto_fix(self, script_path: Path, fix_type: str, context: Dict) -> bool:
        """
        Called before auto-fix application

        Returns:
            True to allow fix, False to block
        """
        return True

    def on_post_auto_fix(self, script_path: Path, fix_type: str, context: Dict):
        """Called after auto-fix application"""
        pass

    def on_error(self, error: Exception, context: Dict):
        """Called when an error occurs"""
        pass


class PluginManager:
    """Manage PyManager plugins"""

    def __init__(self, config: Dict, plugins_dir: Optional[Path] = None):
        self.config = config
        self.plugins_dir = plugins_dir or Path.home() / '.pymanager' / 'plugins'
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

        self.plugins: Dict[str, Plugin] = {}
        self.hooks: Dict[str, List[Plugin]] = {hook: [] for hook in self._get_all_hooks()}

    def _get_all_hooks(self) -> List[str]:
        """Get all available hook names"""
        return [
            getattr(PluginHook, attr)
            for attr in dir(PluginHook)
            if not attr.startswith('_')
        ]

    def discover_plugins(self):
        """Discover plugins in plugins directory"""
        plugin_files = list(self.plugins_dir.glob('*.py'))

        print(f"🔍 Discovering plugins in {self.plugins_dir}")
        print(f"   Found {len(plugin_files)} plugin files")

        for plugin_file in plugin_files:
            if plugin_file.name.startswith('_'):
                continue

            try:
                self.load_plugin(plugin_file)
            except Exception as e:
                print(f"   ⚠️  Failed to load {plugin_file.name}: {e}")

    def load_plugin(self, plugin_path: Path):
        """Load a single plugin"""
        module_name = f"pymanager_plugin_{plugin_path.stem}"

        # Load module
        spec = importlib.util.spec_from_file_location(module_name, plugin_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load plugin spec from {plugin_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        # Find Plugin subclasses
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Plugin) and obj is not Plugin:
                # Instantiate plugin
                plugin_instance = obj(self.config)

                # Register plugin
                self.plugins[plugin_instance.name] = plugin_instance

                # Register hooks
                for hook in plugin_instance.hooks:
                    if hook in self.hooks:
                        self.hooks[hook].append(plugin_instance)

                print(f"   ✅ Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")

    def execute_hook(self, hook_name: str, *args, **kwargs) -> Any:
        """
        Execute all plugins subscribed to a hook

        Returns:
            Result depends on hook type
        """
        if hook_name not in self.hooks:
            return None

        plugins = self.hooks[hook_name]

        # Execute each plugin
        for plugin in plugins:
            if not plugin.enabled:
                continue

            try:
                # Call appropriate plugin method
                method_name = f"on_{hook_name}"
                method = getattr(plugin, method_name, None)

                if method:
                    result = method(*args, **kwargs)

                    # Some hooks can return values that affect execution
                    if result is not None:
                        return result

            except Exception as e:
                print(f"⚠️  Plugin {plugin.name} error in {hook_name}: {e}")

        return None

    def list_plugins(self):
        """List all loaded plugins"""
        print("=" * 70)
        print("PyManager Plugins")
        print("=" * 70)

        if not self.plugins:
            print("No plugins loaded")
        else:
            for name, plugin in self.plugins.items():
                status = "✅ Enabled" if plugin.enabled else "❌ Disabled"
                print(f"{name:30} v{plugin.version:10} {status}")
                print(f"  {plugin.description}")
                if plugin.hooks:
                    print(f"  Hooks: {', '.join(plugin.hooks)}")
                print()

        print("=" * 70)

    def enable_plugin(self, plugin_name: str):
        """Enable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = True
            print(f"✅ Enabled plugin: {plugin_name}")
        else:
            print(f"❌ Plugin not found: {plugin_name}")

    def disable_plugin(self, plugin_name: str):
        """Disable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = False
            print(f"✅ Disabled plugin: {plugin_name}")
        else:
            print(f"❌ Plugin not found: {plugin_name}")


# Example plugin
class ExampleLoggingPlugin(Plugin):
    """Example plugin that logs all executions"""

    @property
    def name(self) -> str:
        return "logging_example"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Example plugin that logs all script executions"

    @property
    def hooks(self) -> List[str]:
        return [
            PluginHook.PRE_EXECUTION,
            PluginHook.POST_EXECUTION,
        ]

    def on_pre_execution(self, script_path: Path, python_version: str, context: Dict) -> bool:
        print(f"[LoggingPlugin] Executing {script_path.name} with Python {python_version}")
        return True

    def on_post_execution(self, script_path: Path, exit_code: int, context: Dict):
        status = "SUCCESS" if exit_code == 0 else "FAILED"
        print(f"[LoggingPlugin] Execution {status} (exit code: {exit_code})")


def create_example_plugin():
    """Create example plugin file"""
    example_plugin = '''#!/usr/bin/env python3
"""
Example PyManager Plugin
This is a template for creating custom PyManager plugins
"""

from pathlib import Path
from typing import Dict, List, Optional
from plugin_system import Plugin, PluginHook


class MyCustomPlugin(Plugin):
    """Custom plugin description"""

    @property
    def name(self) -> str:
        return "my_custom_plugin"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "My custom PyManager plugin"

    @property
    def hooks(self) -> List[str]:
        return [
            PluginHook.PRE_EXECUTION,
            PluginHook.POST_EXECUTION,
        ]

    def on_pre_execution(self, script_path: Path, python_version: str, context: Dict) -> bool:
        """Called before script execution"""
        # Add your custom logic here
        print(f"[MyPlugin] About to execute {script_path}")

        # Return True to continue, False to cancel execution
        return True

    def on_post_execution(self, script_path: Path, exit_code: int, context: Dict):
        """Called after script execution"""
        # Add your custom logic here
        print(f"[MyPlugin] Script finished with exit code {exit_code}")
'''

    plugins_dir = Path.home() / '.pymanager' / 'plugins'
    plugins_dir.mkdir(parents=True, exist_ok=True)

    example_file = plugins_dir / 'example_plugin.py'
    example_file.write_text(example_plugin)

    print(f"✅ Created example plugin: {example_file}")


def main():
    """CLI for plugin management"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='PyManager Plugin Manager')
    parser.add_argument('command', choices=[
        'list',
        'enable',
        'disable',
        'create-example'
    ], help='Command to execute')
    parser.add_argument('plugin', nargs='?', help='Plugin name')

    args = parser.parse_args()

    # Load config
    manager_dir = Path(__file__).parent.parent.parent
    config_file = manager_dir / 'pymanager.json'

    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {}

    # Execute command
    if args.command == 'create-example':
        create_example_plugin()
        return

    # Create plugin manager
    plugin_mgr = PluginManager(config)
    plugin_mgr.discover_plugins()

    if args.command == 'list':
        plugin_mgr.list_plugins()

    elif args.command == 'enable':
        if not args.plugin:
            print("❌ Plugin name required")
            sys.exit(1)
        plugin_mgr.enable_plugin(args.plugin)

    elif args.command == 'disable':
        if not args.plugin:
            print("❌ Plugin name required")
            sys.exit(1)
        plugin_mgr.disable_plugin(args.plugin)


if __name__ == '__main__':
    main()
