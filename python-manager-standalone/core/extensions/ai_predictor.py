#!/usr/bin/env python3
"""
PyManager AI Version Predictor
ML-based Python version recommendations using historical data
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple
from collections import Counter


class AIPredictor:
    """ML-based version prediction (simplified heuristic-based approach)"""

    def __init__(self, config: Dict):
        self.config = config
        self.metrics_dir = Path.home() / '.pymanager' / 'metrics'

    def load_historical_data(self) -> List[Dict]:
        """Load historical execution data"""
        sessions = []

        if not self.metrics_dir.exists():
            return sessions

        for session_file in self.metrics_dir.glob('session_*.json'):
            try:
                with open(session_file, 'r') as f:
                    sessions.append(json.load(f))
            except:
                pass

        return sessions

    def analyze_patterns(self, script_path: Path) -> Dict:
        """Analyze historical patterns for script"""
        sessions = self.load_historical_data()

        script_name = script_path.name
        versions_used = []
        success_by_version = Counter()
        failure_by_version = Counter()

        # Scan historical data
        for session in sessions:
            for execution in session.get('metrics', {}).get('executions', []):
                if Path(execution.get('script', '')).name == script_name:
                    version = execution.get('version', '')
                    exit_code = execution.get('exit_code', 1)

                    versions_used.append(version)

                    if exit_code == 0:
                        success_by_version[version] += 1
                    else:
                        failure_by_version[version] += 1

        return {
            'versions_used': Counter(versions_used),
            'success_by_version': success_by_version,
            'failure_by_version': failure_by_version,
            'total_executions': len(versions_used)
        }

    def predict_version(self, script_path: Path) -> Tuple[str, float, str]:
        """
        Predict best Python version for script

        Returns:
            (version, confidence, reason)
        """
        patterns = self.analyze_patterns(script_path)

        if patterns['total_executions'] == 0:
            # No historical data, use heuristics
            return self.heuristic_prediction(script_path)

        # Calculate success rates
        best_version = None
        best_score = 0

        for version in patterns['versions_used']:
            success = patterns['success_by_version'][version]
            failure = patterns['failure_by_version'][version]
            total = success + failure

            if total == 0:
                continue

            success_rate = success / total
            usage_frequency = patterns['versions_used'][version] / patterns['total_executions']

            # Score = success_rate * usage_frequency
            score = success_rate * usage_frequency

            if score > best_score:
                best_score = score
                best_version = version

        if best_version:
            confidence = best_score * 100
            reason = f"Historical data: {patterns['success_by_version'][best_version]} successful runs"
            return best_version, confidence, reason
        else:
            return self.heuristic_prediction(script_path)

    def heuristic_prediction(self, script_path: Path) -> Tuple[str, float, str]:
        """Fallback heuristic prediction"""
        # Read script content
        try:
            with open(script_path, 'r') as f:
                content = f.read().lower()

            # Simple heuristics
            if 'tensorflow' in content or 'torch' in content:
                return '3.11', 75.0, "ML frameworks detected"

            if 'fastapi' in content or 'uvicorn' in content:
                return '3.11', 80.0, "FastAPI framework detected"

            if 'asyncio' in content and 'async def' in content:
                return '3.11', 70.0, "Async code detected"

            if 'typing' in content and ('|' in content or 'Union' in content):
                return '3.10', 65.0, "Modern type hints detected"

        except:
            pass

        # Default
        return '3.11', 50.0, "Default recommendation"

    def recommend_version(self, script_path: Path):
        """Display version recommendation"""
        version, confidence, reason = self.predict_version(script_path)

        print("=" * 70)
        print("AI Version Prediction")
        print("=" * 70)
        print(f"Script: {script_path}")
        print()
        print(f"Recommended Version: Python {version}")
        print(f"Confidence: {confidence:.1f}%")
        print(f"Reason: {reason}")
        print()

        # Show historical patterns
        patterns = self.analyze_patterns(script_path)

        if patterns['total_executions'] > 0:
            print("Historical Data:")
            for ver, count in patterns['versions_used'].most_common(3):
                success = patterns['success_by_version'][ver]
                total = success + patterns['failure_by_version'][ver]
                success_rate = (success / total * 100) if total > 0 else 0

                print(f"  Python {ver}: {count} executions ({success_rate:.0f}% success)")

        print("=" * 70)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='PyManager AI Version Predictor')
    parser.add_argument('script', help='Script to analyze')

    args = parser.parse_args()

    predictor = AIPredictor({})
    predictor.recommend_version(Path(args.script))


if __name__ == '__main__':
    main()
