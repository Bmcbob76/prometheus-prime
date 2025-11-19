#!/usr/bin/env python3
"""
PyManager Metrics Collector - Analytics & Monitoring
Tracks usage patterns, performance metrics, and system health
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import threading


class MetricsCollector:
    """Collect and analyze PyManager usage metrics"""

    def __init__(self, config: Dict, metrics_dir: Optional[Path] = None):
        self.config = config
        self.metrics_dir = metrics_dir or Path.home() / '.pymanager' / 'metrics'
        self.metrics_dir.mkdir(parents=True, exist_ok=True)

        # Metrics configuration
        metrics_config = config.get('metrics', {})
        self.enabled = metrics_config.get('enabled', True)
        self.collect_detailed = metrics_config.get('detailed', False)

        # Current session metrics
        self.session_start = time.time()
        self.session_metrics = {
            'executions': [],
            'version_switches': [],
            'auto_fixes_applied': [],
            'errors': [],
            'cache_hits': 0,
            'cache_misses': 0,
        }

        # Thread safety
        self.lock = threading.Lock()

    def record_execution(self, script_path: Path, python_version: str,
                        execution_time: float, exit_code: int):
        """Record script execution"""
        if not self.enabled:
            return

        with self.lock:
            self.session_metrics['executions'].append({
                'timestamp': time.time(),
                'script': str(script_path),
                'version': python_version,
                'execution_time': execution_time,
                'exit_code': exit_code,
            })

    def record_version_switch(self, script_path: Path, from_version: str, to_version: str, reason: str):
        """Record automatic version switch"""
        if not self.enabled:
            return

        with self.lock:
            self.session_metrics['version_switches'].append({
                'timestamp': time.time(),
                'script': str(script_path),
                'from_version': from_version,
                'to_version': to_version,
                'reason': reason,
            })

    def record_auto_fix(self, script_path: Path, fix_type: str, details: Dict):
        """Record auto-fix application"""
        if not self.enabled:
            return

        with self.lock:
            self.session_metrics['auto_fixes_applied'].append({
                'timestamp': time.time(),
                'script': str(script_path),
                'fix_type': fix_type,
                'details': details,
            })

    def record_error(self, error_type: str, error_message: str, context: Dict):
        """Record error"""
        if not self.enabled:
            return

        with self.lock:
            self.session_metrics['errors'].append({
                'timestamp': time.time(),
                'error_type': error_type,
                'error_message': error_message,
                'context': context,
            })

    def record_cache_hit(self):
        """Record cache hit"""
        if not self.enabled:
            return

        with self.lock:
            self.session_metrics['cache_hits'] += 1

    def record_cache_miss(self):
        """Record cache miss"""
        if not self.enabled:
            return

        with self.lock:
            self.session_metrics['cache_misses'] += 1

    def save_session_metrics(self):
        """Save current session metrics to disk"""
        if not self.enabled:
            return

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            session_file = self.metrics_dir / f'session_{timestamp}.json'

            with self.lock:
                session_data = {
                    'session_start': self.session_start,
                    'session_end': time.time(),
                    'session_duration': time.time() - self.session_start,
                    'metrics': self.session_metrics,
                }

            with open(session_file, 'w') as f:
                json.dump(session_data, f, indent=2)

        except Exception as e:
            # Silently fail - metrics collection is not critical
            pass

    def load_historical_metrics(self, days: int = 30) -> List[Dict]:
        """Load historical metrics from past N days"""
        metrics = []

        try:
            cutoff_time = time.time() - (days * 24 * 3600)

            for session_file in sorted(self.metrics_dir.glob('session_*.json')):
                # Check if file is within time range
                if session_file.stat().st_mtime < cutoff_time:
                    continue

                with open(session_file, 'r') as f:
                    data = json.load(f)
                    metrics.append(data)

        except Exception as e:
            pass

        return metrics

    def analyze_metrics(self, days: int = 7) -> Dict:
        """Analyze metrics and generate insights"""
        historical = self.load_historical_metrics(days)

        analysis = {
            'time_period': f'Last {days} days',
            'total_sessions': len(historical),
            'total_executions': 0,
            'total_execution_time': 0,
            'avg_execution_time': 0,
            'version_usage': Counter(),
            'most_executed_scripts': Counter(),
            'auto_fix_usage': Counter(),
            'error_types': Counter(),
            'success_rate': 0,
            'cache_hit_rate': 0,
        }

        total_cache_hits = 0
        total_cache_misses = 0
        successful_executions = 0
        failed_executions = 0

        for session in historical:
            metrics = session.get('metrics', {})

            # Executions
            executions = metrics.get('executions', [])
            analysis['total_executions'] += len(executions)

            for exec_data in executions:
                analysis['total_execution_time'] += exec_data.get('execution_time', 0)
                analysis['version_usage'][exec_data.get('version', 'unknown')] += 1

                script_name = Path(exec_data.get('script', '')).name
                analysis['most_executed_scripts'][script_name] += 1

                if exec_data.get('exit_code', 0) == 0:
                    successful_executions += 1
                else:
                    failed_executions += 1

            # Auto-fixes
            auto_fixes = metrics.get('auto_fixes_applied', [])
            for fix in auto_fixes:
                analysis['auto_fix_usage'][fix.get('fix_type', 'unknown')] += 1

            # Errors
            errors = metrics.get('errors', [])
            for error in errors:
                analysis['error_types'][error.get('error_type', 'unknown')] += 1

            # Cache
            total_cache_hits += metrics.get('cache_hits', 0)
            total_cache_misses += metrics.get('cache_misses', 0)

        # Calculate averages
        if analysis['total_executions'] > 0:
            analysis['avg_execution_time'] = analysis['total_execution_time'] / analysis['total_executions']
            analysis['success_rate'] = (successful_executions / analysis['total_executions']) * 100

        total_cache_requests = total_cache_hits + total_cache_misses
        if total_cache_requests > 0:
            analysis['cache_hit_rate'] = (total_cache_hits / total_cache_requests) * 100

        return analysis

    def generate_report(self, days: int = 7) -> str:
        """Generate human-readable metrics report"""
        analysis = self.analyze_metrics(days)

        report = []
        report.append("=" * 70)
        report.append("PyManager Usage Analytics")
        report.append("=" * 70)
        report.append(f"Time Period: {analysis['time_period']}")
        report.append(f"Total Sessions: {analysis['total_sessions']}")
        report.append("")

        # Execution statistics
        report.append("Execution Statistics:")
        report.append(f"  Total Executions: {analysis['total_executions']}")
        report.append(f"  Success Rate: {analysis['success_rate']:.1f}%")
        report.append(f"  Avg Execution Time: {analysis['avg_execution_time']*1000:.1f}ms")
        report.append("")

        # Python version usage
        if analysis['version_usage']:
            report.append("Python Version Usage:")
            for version, count in analysis['version_usage'].most_common(5):
                percentage = (count / analysis['total_executions']) * 100
                report.append(f"  {version:10} {count:5} executions ({percentage:.1f}%)")
            report.append("")

        # Most executed scripts
        if analysis['most_executed_scripts']:
            report.append("Most Executed Scripts (Top 10):")
            for script, count in analysis['most_executed_scripts'].most_common(10):
                report.append(f"  {script:40} {count:5} times")
            report.append("")

        # Auto-fix usage
        if analysis['auto_fix_usage']:
            report.append("Auto-Fix Usage:")
            for fix_type, count in analysis['auto_fix_usage'].most_common():
                report.append(f"  {fix_type:30} {count:5} times")
            report.append("")

        # Error types
        if analysis['error_types']:
            report.append("Error Types:")
            for error_type, count in analysis['error_types'].most_common():
                report.append(f"  {error_type:30} {count:5} times")
            report.append("")

        # Cache performance
        report.append("Cache Performance:")
        report.append(f"  Hit Rate: {analysis['cache_hit_rate']:.1f}%")
        report.append("")

        report.append("=" * 70)

        return '\n'.join(report)

    def show_report(self, days: int = 7):
        """Display metrics report"""
        print(self.generate_report(days))

    def export_metrics(self, output_file: Path, days: int = 30):
        """Export metrics to JSON file"""
        metrics = self.load_historical_metrics(days)
        analysis = self.analyze_metrics(days)

        export_data = {
            'generated_at': datetime.now().isoformat(),
            'time_period_days': days,
            'analysis': {
                'total_sessions': analysis['total_sessions'],
                'total_executions': analysis['total_executions'],
                'success_rate': analysis['success_rate'],
                'avg_execution_time': analysis['avg_execution_time'],
                'cache_hit_rate': analysis['cache_hit_rate'],
                'version_usage': dict(analysis['version_usage']),
                'most_executed_scripts': dict(analysis['most_executed_scripts'].most_common(20)),
                'auto_fix_usage': dict(analysis['auto_fix_usage']),
                'error_types': dict(analysis['error_types']),
            },
            'raw_sessions': metrics if self.collect_detailed else []
        }

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)

        print(f"✅ Metrics exported to {output_file}")

    def cleanup_old_metrics(self, days: int = 90):
        """Delete metrics older than N days"""
        cutoff_time = time.time() - (days * 24 * 3600)
        deleted_count = 0

        for session_file in self.metrics_dir.glob('session_*.json'):
            if session_file.stat().st_mtime < cutoff_time:
                session_file.unlink()
                deleted_count += 1

        print(f"✅ Deleted {deleted_count} old metric files")


def main():
    """CLI for metrics collection"""
    import argparse

    parser = argparse.ArgumentParser(description='PyManager Metrics Collector')
    parser.add_argument('command', choices=['report', 'export', 'cleanup', 'enable', 'disable'],
                        help='Command to execute')
    parser.add_argument('--days', type=int, default=7, help='Number of days to analyze')
    parser.add_argument('--output', type=str, help='Output file for export')

    args = parser.parse_args()

    # Load config
    manager_dir = Path(__file__).parent.parent.parent
    config_file = manager_dir / 'pymanager.json'

    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        config = {}

    # Create metrics collector
    metrics = MetricsCollector(config)

    # Execute command
    if args.command == 'report':
        metrics.show_report(days=args.days)

    elif args.command == 'export':
        output_file = Path(args.output) if args.output else Path('pymanager_metrics.json')
        metrics.export_metrics(output_file, days=args.days)

    elif args.command == 'cleanup':
        metrics.cleanup_old_metrics(days=args.days)

    elif args.command == 'enable':
        config.setdefault('metrics', {})['enabled'] = True
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Metrics collection enabled")

    elif args.command == 'disable':
        config.setdefault('metrics', {})['enabled'] = False
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Metrics collection disabled")


if __name__ == '__main__':
    main()
