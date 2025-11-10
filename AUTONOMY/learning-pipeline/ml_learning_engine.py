#!/usr/bin/env python3
"""
PROMETHEUS PRIME - REAL-TIME ML LEARNING PIPELINE
Continuous learning from engagement results with adaptive TTPs

Authority Level: 11.0
Commander: Bobby Don McWilliams II
AUTONOMY CORE - ADAPTIVE INTELLIGENCE
"""

import json
import logging
import sys
import pickle
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict
import numpy as np

# ML libraries
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available - ML features disabled")


@dataclass
class ExploitAttempt:
    """Record of an exploit attempt."""
    attempt_id: str
    timestamp: float
    target_ip: str
    target_os: Optional[str]
    target_service: str
    target_version: Optional[str]
    exploit_name: str
    exploit_category: str
    tool_used: str
    parameters: Dict[str, Any]
    success: bool
    execution_time: float
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ToolEffectiveness:
    """Effectiveness metrics for a tool."""
    tool_name: str
    total_uses: int
    successful_uses: int
    failed_uses: int
    avg_execution_time: float
    success_rate: float
    target_types: Dict[str, int]  # target_type -> count
    last_updated: float


@dataclass
class TargetProfile:
    """Profile of a target environment."""
    profile_id: str
    os_type: str
    services: List[str]
    versions: Dict[str, str]
    vulnerabilities: List[str]
    successful_exploits: List[str]
    failed_exploits: List[str]
    estimated_difficulty: float  # 0.0 to 1.0


class MLLearningEngine:
    """
    Real-time machine learning engine that learns from engagement results
    and adapts tactics, techniques, and procedures.
    """

    def __init__(self, model_dir: str = '/var/lib/prometheus/models'):
        """
        Initialize ML learning engine.

        Args:
            model_dir: Directory to store trained models
        """
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ML_ENGINE - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/ml_engine.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('ML_ENGINE')

        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Training data
        self.exploit_history: List[ExploitAttempt] = []
        self.tool_effectiveness: Dict[str, ToolEffectiveness] = {}
        self.target_profiles: Dict[str, TargetProfile] = {}

        # ML Models
        self.exploit_success_predictor = None
        self.tool_selector = None
        self.target_classifier = None

        # Feature encoders
        self.os_encoder = LabelEncoder()
        self.service_encoder = LabelEncoder()
        self.tool_encoder = LabelEncoder()
        self.scaler = StandardScaler()

        # Statistics
        self.stats = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'models_trained': 0,
            'predictions_made': 0,
            'correct_predictions': 0
        }

        # Load existing models
        self._load_models()

        self.logger.info("ML Learning Engine initialized")
        self.logger.info(f"scikit-learn available: {SKLEARN_AVAILABLE}")

    def record_exploit_attempt(self, attempt: ExploitAttempt):
        """
        Record an exploit attempt for learning.

        Args:
            attempt: ExploitAttempt record
        """
        self.exploit_history.append(attempt)
        self.stats['total_attempts'] += 1

        if attempt.success:
            self.stats['successful_attempts'] += 1

        # Update tool effectiveness
        self._update_tool_effectiveness(attempt)

        # Update target profile
        self._update_target_profile(attempt)

        self.logger.info(f"Recorded attempt: {attempt.exploit_name} on {attempt.target_ip} - "
                        f"{'SUCCESS' if attempt.success else 'FAILURE'}")

        # Trigger model update if we have enough data
        if len(self.exploit_history) % 50 == 0:  # Retrain every 50 attempts
            self.logger.info("Triggering model retraining...")
            self.train_models()

    def _update_tool_effectiveness(self, attempt: ExploitAttempt):
        """Update tool effectiveness metrics."""
        tool = attempt.tool_used

        if tool not in self.tool_effectiveness:
            self.tool_effectiveness[tool] = ToolEffectiveness(
                tool_name=tool,
                total_uses=0,
                successful_uses=0,
                failed_uses=0,
                avg_execution_time=0.0,
                success_rate=0.0,
                target_types={},
                last_updated=time.time()
            )

        metrics = self.tool_effectiveness[tool]
        metrics.total_uses += 1

        if attempt.success:
            metrics.successful_uses += 1
        else:
            metrics.failed_uses += 1

        # Update average execution time
        metrics.avg_execution_time = (
            (metrics.avg_execution_time * (metrics.total_uses - 1) + attempt.execution_time)
            / metrics.total_uses
        )

        # Update success rate
        metrics.success_rate = metrics.successful_uses / metrics.total_uses

        # Track target types
        target_type = attempt.target_service
        metrics.target_types[target_type] = metrics.target_types.get(target_type, 0) + 1
        metrics.last_updated = time.time()

    def _update_target_profile(self, attempt: ExploitAttempt):
        """Update target profile."""
        profile_id = attempt.target_ip

        if profile_id not in self.target_profiles:
            self.target_profiles[profile_id] = TargetProfile(
                profile_id=profile_id,
                os_type=attempt.target_os or 'unknown',
                services=[],
                versions={},
                vulnerabilities=[],
                successful_exploits=[],
                failed_exploits=[],
                estimated_difficulty=0.5
            )

        profile = self.target_profiles[profile_id]

        # Update services
        if attempt.target_service not in profile.services:
            profile.services.append(attempt.target_service)

        # Update versions
        if attempt.target_version:
            profile.versions[attempt.target_service] = attempt.target_version

        # Update exploit lists
        if attempt.success:
            if attempt.exploit_name not in profile.successful_exploits:
                profile.successful_exploits.append(attempt.exploit_name)
        else:
            if attempt.exploit_name not in profile.failed_exploits:
                profile.failed_exploits.append(attempt.exploit_name)

        # Update difficulty estimate (based on success rate)
        total_attempts = len(profile.successful_exploits) + len(profile.failed_exploits)
        if total_attempts > 0:
            profile.estimated_difficulty = 1.0 - (len(profile.successful_exploits) / total_attempts)

    def train_models(self):
        """Train/update all ML models."""
        if not SKLEARN_AVAILABLE:
            self.logger.warning("scikit-learn not available - skipping training")
            return

        if len(self.exploit_history) < 10:
            self.logger.warning("Insufficient data for training (need at least 10 samples)")
            return

        self.logger.info(f"Training models with {len(self.exploit_history)} samples...")

        # Train exploit success predictor
        self._train_exploit_success_predictor()

        # Train tool selector
        self._train_tool_selector()

        # Train target classifier
        self._train_target_classifier()

        self.stats['models_trained'] += 1
        self.logger.info("Model training complete")

        # Save models
        self._save_models()

    def _train_exploit_success_predictor(self):
        """Train model to predict exploit success probability."""
        # Prepare features
        X = []
        y = []

        # Fit encoders on all data first
        all_os = [a.target_os or 'unknown' for a in self.exploit_history]
        all_services = [a.target_service for a in self.exploit_history]
        all_tools = [a.tool_used for a in self.exploit_history]

        self.os_encoder.fit(all_os)
        self.service_encoder.fit(all_services)
        self.tool_encoder.fit(all_tools)

        for attempt in self.exploit_history:
            features = self._extract_features(attempt)
            X.append(features)
            y.append(1 if attempt.success else 0)

        X = np.array(X)
        y = np.array(y)

        # Split data
        if len(X) >= 20:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
        else:
            X_train, X_test, y_train, y_test = X, X, y, y

        # Scale features
        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)

        # Train model
        self.exploit_success_predictor = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.exploit_success_predictor.fit(X_train, y_train)

        # Evaluate
        y_pred = self.exploit_success_predictor.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        self.logger.info(f"Exploit success predictor trained - Accuracy: {accuracy:.2%}")

    def _train_tool_selector(self):
        """Train model to select best tool for a target."""
        # Prepare features (target characteristics) and labels (best tool)
        X = []
        y = []

        # Group by target to find best tool
        target_tools = defaultdict(list)

        for attempt in self.exploit_history:
            target_key = f"{attempt.target_os}_{attempt.target_service}"
            target_tools[target_key].append((attempt.tool_used, attempt.success))

        # For each target, find tool with highest success rate
        for target_key, tools in target_tools.items():
            if len(tools) < 3:  # Need at least 3 attempts
                continue

            tool_success = defaultdict(lambda: {'success': 0, 'total': 0})
            for tool, success in tools:
                tool_success[tool]['total'] += 1
                if success:
                    tool_success[tool]['success'] += 1

            # Find best tool
            best_tool = max(
                tool_success.items(),
                key=lambda x: x[1]['success'] / x[1]['total'] if x[1]['total'] > 0 else 0
            )[0]

            # Create training sample for each attempt on this target
            for attempt in self.exploit_history:
                attempt_key = f"{attempt.target_os}_{attempt.target_service}"
                if attempt_key == target_key:
                    features = self._extract_target_features(attempt)
                    X.append(features)
                    y.append(best_tool)

        if len(X) < 10:
            self.logger.warning("Insufficient data for tool selector training")
            return

        X = np.array(X)

        # Encode tool labels
        y_encoded = self.tool_encoder.transform(y)

        # Train model
        self.tool_selector = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
        self.tool_selector.fit(X, y_encoded)

        self.logger.info("Tool selector model trained")

    def _train_target_classifier(self):
        """Train model to classify target difficulty."""
        X = []
        y = []

        for profile in self.target_profiles.values():
            features = self._extract_profile_features(profile)
            X.append(features)

            # Classify difficulty: 0=easy, 1=medium, 2=hard
            if profile.estimated_difficulty < 0.3:
                y.append(0)
            elif profile.estimated_difficulty < 0.7:
                y.append(1)
            else:
                y.append(2)

        if len(X) < 10:
            self.logger.warning("Insufficient target profiles for classifier training")
            return

        X = np.array(X)
        y = np.array(y)

        # Train model
        self.target_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            random_state=42
        )
        self.target_classifier.fit(X, y)

        self.logger.info("Target classifier trained")

    def _extract_features(self, attempt: ExploitAttempt) -> List[float]:
        """Extract features from an exploit attempt."""
        features = []

        # OS type (encoded)
        os_encoded = self.os_encoder.transform([attempt.target_os or 'unknown'])[0]
        features.append(float(os_encoded))

        # Service (encoded)
        service_encoded = self.service_encoder.transform([attempt.target_service])[0]
        features.append(float(service_encoded))

        # Tool (encoded)
        tool_encoded = self.tool_encoder.transform([attempt.tool_used])[0]
        features.append(float(tool_encoded))

        # Exploit category (hash)
        features.append(float(hash(attempt.exploit_category) % 1000))

        # Number of parameters
        features.append(float(len(attempt.parameters)))

        return features

    def _extract_target_features(self, attempt: ExploitAttempt) -> List[float]:
        """Extract target-specific features."""
        features = []

        # OS type
        os_encoded = self.os_encoder.transform([attempt.target_os or 'unknown'])[0]
        features.append(float(os_encoded))

        # Service
        service_encoded = self.service_encoder.transform([attempt.target_service])[0]
        features.append(float(service_encoded))

        # Has version info
        features.append(1.0 if attempt.target_version else 0.0)

        return features

    def _extract_profile_features(self, profile: TargetProfile) -> List[float]:
        """Extract features from a target profile."""
        features = []

        # Number of services
        features.append(float(len(profile.services)))

        # Number of known vulnerabilities
        features.append(float(len(profile.vulnerabilities)))

        # Success/failure ratio
        total = len(profile.successful_exploits) + len(profile.failed_exploits)
        if total > 0:
            features.append(float(len(profile.successful_exploits) / total))
        else:
            features.append(0.5)

        # Estimated difficulty
        features.append(profile.estimated_difficulty)

        return features

    def predict_exploit_success(self,
                               target_os: str,
                               target_service: str,
                               tool: str,
                               exploit_category: str,
                               parameters: Dict) -> float:
        """
        Predict probability of exploit success.

        Args:
            target_os: Target operating system
            target_service: Target service
            tool: Tool to use
            exploit_category: Category of exploit
            parameters: Exploit parameters

        Returns:
            Probability of success (0.0 to 1.0)
        """
        if not self.exploit_success_predictor:
            return 0.5  # Default if no model

        # Create dummy attempt for feature extraction
        dummy_attempt = ExploitAttempt(
            attempt_id='prediction',
            timestamp=time.time(),
            target_ip='0.0.0.0',
            target_os=target_os,
            target_service=target_service,
            target_version=None,
            exploit_name='unknown',
            exploit_category=exploit_category,
            tool_used=tool,
            parameters=parameters,
            success=False,
            execution_time=0.0
        )

        features = self._extract_features(dummy_attempt)
        features_scaled = self.scaler.transform([features])

        # Predict probability
        proba = self.exploit_success_predictor.predict_proba(features_scaled)[0]
        success_prob = proba[1]  # Probability of class 1 (success)

        self.stats['predictions_made'] += 1

        self.logger.debug(f"Predicted success probability: {success_prob:.2%}")
        return float(success_prob)

    def recommend_tool(self, target_os: str, target_service: str) -> str:
        """
        Recommend best tool for a target.

        Args:
            target_os: Target operating system
            target_service: Target service

        Returns:
            Recommended tool name
        """
        if not self.tool_selector:
            # Fallback: Return tool with highest overall success rate
            if self.tool_effectiveness:
                return max(
                    self.tool_effectiveness.values(),
                    key=lambda x: x.success_rate
                ).tool_name
            return "nmap"  # Default

        # Create features
        dummy_attempt = ExploitAttempt(
            attempt_id='recommendation',
            timestamp=time.time(),
            target_ip='0.0.0.0',
            target_os=target_os,
            target_service=target_service,
            target_version=None,
            exploit_name='unknown',
            exploit_category='unknown',
            tool_used='unknown',
            parameters={},
            success=False,
            execution_time=0.0
        )

        features = self._extract_target_features(dummy_attempt)

        # Predict best tool
        tool_encoded = self.tool_selector.predict([features])[0]
        recommended_tool = self.tool_encoder.inverse_transform([int(tool_encoded)])[0]

        self.logger.info(f"Recommended tool for {target_os}/{target_service}: {recommended_tool}")
        return str(recommended_tool)

    def get_tool_rankings(self, target_type: Optional[str] = None) -> List[Tuple[str, float]]:
        """
        Get tools ranked by effectiveness.

        Args:
            target_type: Optional filter by target type

        Returns:
            List of (tool_name, success_rate) tuples, sorted by success rate
        """
        rankings = []

        for tool_name, metrics in self.tool_effectiveness.items():
            if target_type and target_type not in metrics.target_types:
                continue

            rankings.append((tool_name, metrics.success_rate))

        rankings.sort(key=lambda x: x[1], reverse=True)
        return rankings

    def get_adaptive_ttps(self, target_profile: TargetProfile) -> List[str]:
        """
        Get adaptive tactics, techniques, and procedures for a target.

        Args:
            target_profile: Target profile

        Returns:
            List of recommended TTPs
        """
        ttps = []

        # Based on successful exploits
        if target_profile.successful_exploits:
            ttps.append(f"Repeat successful: {', '.join(target_profile.successful_exploits[:3])}")

        # Based on target difficulty
        if target_profile.estimated_difficulty < 0.3:
            ttps.append("Target is easy - try direct exploitation")
        elif target_profile.estimated_difficulty < 0.7:
            ttps.append("Target is medium - combine multiple techniques")
        else:
            ttps.append("Target is hard - use advanced evasion and chaining")

        # Based on services
        if 'smb' in target_profile.services:
            ttps.append("SMB detected - try lateral movement via PsExec/WMIExec")
        if 'ssh' in target_profile.services:
            ttps.append("SSH detected - try credential brute force or key-based auth")

        return ttps

    def _save_models(self):
        """Save trained models to disk."""
        if not SKLEARN_AVAILABLE:
            return

        try:
            # Save exploit success predictor
            if self.exploit_success_predictor:
                with open(self.model_dir / 'exploit_success_predictor.pkl', 'wb') as f:
                    pickle.dump(self.exploit_success_predictor, f)

            # Save tool selector
            if self.tool_selector:
                with open(self.model_dir / 'tool_selector.pkl', 'wb') as f:
                    pickle.dump(self.tool_selector, f)

            # Save target classifier
            if self.target_classifier:
                with open(self.model_dir / 'target_classifier.pkl', 'wb') as f:
                    pickle.dump(self.target_classifier, f)

            # Save encoders and scaler
            with open(self.model_dir / 'encoders.pkl', 'wb') as f:
                pickle.dump({
                    'os_encoder': self.os_encoder,
                    'service_encoder': self.service_encoder,
                    'tool_encoder': self.tool_encoder,
                    'scaler': self.scaler
                }, f)

            # Save metrics
            with open(self.model_dir / 'tool_effectiveness.json', 'w') as f:
                metrics_dict = {
                    name: {
                        'tool_name': m.tool_name,
                        'total_uses': m.total_uses,
                        'successful_uses': m.successful_uses,
                        'success_rate': m.success_rate,
                        'avg_execution_time': m.avg_execution_time
                    }
                    for name, m in self.tool_effectiveness.items()
                }
                json.dump(metrics_dict, f, indent=2)

            self.logger.info(f"Models saved to {self.model_dir}")

        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")

    def _load_models(self):
        """Load trained models from disk."""
        if not SKLEARN_AVAILABLE:
            return

        try:
            # Load exploit success predictor
            predictor_path = self.model_dir / 'exploit_success_predictor.pkl'
            if predictor_path.exists():
                with open(predictor_path, 'rb') as f:
                    self.exploit_success_predictor = pickle.load(f)

            # Load tool selector
            selector_path = self.model_dir / 'tool_selector.pkl'
            if selector_path.exists():
                with open(selector_path, 'rb') as f:
                    self.tool_selector = pickle.load(f)

            # Load target classifier
            classifier_path = self.model_dir / 'target_classifier.pkl'
            if classifier_path.exists():
                with open(classifier_path, 'rb') as f:
                    self.target_classifier = pickle.load(f)

            # Load encoders and scaler
            encoders_path = self.model_dir / 'encoders.pkl'
            if encoders_path.exists():
                with open(encoders_path, 'rb') as f:
                    encoders = pickle.load(f)
                    self.os_encoder = encoders['os_encoder']
                    self.service_encoder = encoders['service_encoder']
                    self.tool_encoder = encoders['tool_encoder']
                    self.scaler = encoders['scaler']

            self.logger.info(f"Models loaded from {self.model_dir}")

        except Exception as e:
            self.logger.warning(f"Failed to load models: {e}")

    def get_statistics(self) -> Dict:
        """Get learning engine statistics."""
        return {
            **self.stats,
            'exploit_history_size': len(self.exploit_history),
            'tools_tracked': len(self.tool_effectiveness),
            'targets_profiled': len(self.target_profiles),
            'models_available': {
                'exploit_success_predictor': self.exploit_success_predictor is not None,
                'tool_selector': self.tool_selector is not None,
                'target_classifier': self.target_classifier is not None
            },
            'prediction_accuracy': (
                self.stats['correct_predictions'] / self.stats['predictions_made']
                if self.stats['predictions_made'] > 0 else 0.0
            )
        }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Initialize ML engine
    ml_engine = MLLearningEngine()

    print("ML Learning Engine initialized\n")

    # Simulate some exploit attempts
    print("Simulating exploit attempts...")

    for i in range(25):
        attempt = ExploitAttempt(
            attempt_id=f"attempt_{i}",
            timestamp=time.time(),
            target_ip=f"192.168.1.{10 + (i % 5)}",
            target_os=['windows', 'linux'][i % 2],
            target_service=['smb', 'ssh', 'http'][i % 3],
            target_version=None,
            exploit_name=f"exploit_{i % 10}",
            exploit_category=['remote', 'local', 'web'][i % 3],
            tool_used=['metasploit', 'nmap', 'sqlmap'][i % 3],
            parameters={'param1': 'value1'},
            success=(i % 3 == 0),  # 33% success rate
            execution_time=float(10 + (i % 20))
        )
        ml_engine.record_exploit_attempt(attempt)
        time.sleep(0.1)

    print("\nTraining models...")
    ml_engine.train_models()

    # Make predictions
    print("\nMaking predictions...")
    prob = ml_engine.predict_exploit_success(
        target_os='windows',
        target_service='smb',
        tool='metasploit',
        exploit_category='remote',
        parameters={}
    )
    print(f"Predicted success probability: {prob:.2%}")

    # Get tool recommendation
    print("\nGetting tool recommendation...")
    tool = ml_engine.recommend_tool('linux', 'ssh')
    print(f"Recommended tool: {tool}")

    # Get tool rankings
    print("\nTool effectiveness rankings:")
    for tool_name, success_rate in ml_engine.get_tool_rankings():
        print(f"  {tool_name}: {success_rate:.1%}")

    # Statistics
    print("\nML Engine Statistics:")
    stats = ml_engine.get_statistics()
    print(json.dumps(stats, indent=2))
