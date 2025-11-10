#!/usr/bin/env python3
"""
PROMETHEUS PRIME - INFRASTRUCTURE AUTO-SCALING
Cloud resource management for large-scale autonomous operations

Authority Level: 11.0
Commander: Bobby Don McWilliams II
AUTONOMY CORE - INFINITE SCALE
"""

import json
import logging
import sys
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum


class CloudProvider(Enum):
    """Supported cloud providers."""
    DIGITAL_OCEAN = "digitalocean"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    LINODE = "linode"


class InstanceStatus(Enum):
    """Instance status."""
    PROVISIONING = "provisioning"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    TERMINATED = "terminated"


@dataclass
class CloudInstance:
    """A cloud instance."""
    instance_id: str
    provider: CloudProvider
    instance_type: str
    ip_address: Optional[str]
    region: str
    status: InstanceStatus
    created_at: float
    cost_per_hour: float
    purpose: str  # 'scanner', 'exploit', 'c2', 'pivot'
    tags: Dict[str, str]


@dataclass
class ScalingConfig:
    """Auto-scaling configuration."""
    min_instances: int
    max_instances: int
    target_instances: int
    scale_up_threshold: float  # CPU/task load threshold
    scale_down_threshold: float
    cooldown_seconds: int  # Time between scaling actions


class InfrastructureAutoscaler:
    """
    Autonomous infrastructure scaling for large engagements.
    Integrates with Axiom, Terraform, and cloud provider APIs.
    """

    def __init__(self,
                 default_provider: CloudProvider = CloudProvider.DIGITAL_OCEAN,
                 axiom_path: str = '/root/.axiom',
                 terraform_dir: str = '/var/lib/prometheus/terraform'):
        """
        Initialize infrastructure autoscaler.

        Args:
            default_provider: Default cloud provider
            axiom_path: Path to Axiom installation
            terraform_dir: Terraform configuration directory
        """
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - INFRA_SCALE - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/infra_scaling.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('INFRA_SCALE')

        self.default_provider = default_provider
        self.axiom_path = Path(axiom_path)
        self.terraform_dir = Path(terraform_dir)
        self.terraform_dir.mkdir(parents=True, exist_ok=True)

        # Check for Axiom
        self.axiom_available = self._check_axiom()

        # Active instances
        self.instances: Dict[str, CloudInstance] = {}

        # Scaling configuration
        self.scaling_config = ScalingConfig(
            min_instances=1,
            max_instances=100,
            target_instances=5,
            scale_up_threshold=0.8,  # 80% load
            scale_down_threshold=0.3,  # 30% load
            cooldown_seconds=300  # 5 minutes
        )

        # State
        self.last_scaling_action = 0.0
        self.total_cost = 0.0

        # Statistics
        self.stats = {
            'total_provisioned': 0,
            'total_terminated': 0,
            'current_instances': 0,
            'scale_up_events': 0,
            'scale_down_events': 0,
            'total_cost_usd': 0.0
        }

        self.logger.info("Infrastructure Autoscaler initialized")
        self.logger.info(f"Default provider: {default_provider.value}")
        self.logger.info(f"Axiom available: {self.axiom_available}")

    def _check_axiom(self) -> bool:
        """Check if Axiom is installed and configured."""
        try:
            result = subprocess.run(
                ['axiom-ls'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.warning("Axiom not found or not configured")
            return False

    def provision_instance(self,
                          purpose: str,
                          instance_type: str = "s-1vcpu-1gb",
                          region: str = "nyc3") -> Optional[CloudInstance]:
        """
        Provision a cloud instance.

        Args:
            purpose: Purpose ('scanner', 'exploit', 'c2', 'pivot')
            instance_type: Instance type
            region: Region

        Returns:
            CloudInstance if successful
        """
        # Check if we've reached max instances
        if len(self.instances) >= self.scaling_config.max_instances:
            self.logger.warning(f"Max instances reached: {self.scaling_config.max_instances}")
            return None

        instance_id = f"prom-{purpose}-{int(time.time())}"

        self.logger.info(f"Provisioning instance: {instance_id} for {purpose}")

        if self.axiom_available:
            # Use Axiom to provision
            instance = self._provision_via_axiom(instance_id, purpose, instance_type, region)
        else:
            # Use Terraform
            instance = self._provision_via_terraform(instance_id, purpose, instance_type, region)

        if instance:
            self.instances[instance_id] = instance
            self.stats['total_provisioned'] += 1
            self.stats['current_instances'] = len(self.instances)

            self.logger.info(f"✓ Instance provisioned: {instance_id} @ {instance.ip_address}")
            return instance

        return None

    def _provision_via_axiom(self,
                            instance_id: str,
                            purpose: str,
                            instance_type: str,
                            region: str) -> Optional[CloudInstance]:
        """Provision instance via Axiom."""
        try:
            # Axiom init command
            cmd = [
                'axiom-init',
                instance_id,
                '--region', region,
                '--size', instance_type
            ]

            self.logger.debug(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )

            if result.returncode == 0:
                # Parse output to get IP
                ip_address = self._parse_axiom_ip(result.stdout)

                instance = CloudInstance(
                    instance_id=instance_id,
                    provider=self.default_provider,
                    instance_type=instance_type,
                    ip_address=ip_address,
                    region=region,
                    status=InstanceStatus.RUNNING,
                    created_at=time.time(),
                    cost_per_hour=self._get_instance_cost(instance_type),
                    purpose=purpose,
                    tags={'prometheus': 'true', 'purpose': purpose}
                )

                return instance
            else:
                self.logger.error(f"Axiom provisioning failed: {result.stderr}")
                return None

        except Exception as e:
            self.logger.error(f"Axiom provisioning error: {e}")
            return None

    def _provision_via_terraform(self,
                                instance_id: str,
                                purpose: str,
                                instance_type: str,
                                region: str) -> Optional[CloudInstance]:
        """Provision instance via Terraform."""
        # Create Terraform configuration
        tf_config = self._generate_terraform_config(
            instance_id, instance_type, region
        )

        tf_file = self.terraform_dir / f"{instance_id}.tf"
        with open(tf_file, 'w') as f:
            f.write(tf_config)

        try:
            # Initialize Terraform
            subprocess.run(
                ['terraform', 'init'],
                cwd=self.terraform_dir,
                capture_output=True,
                timeout=60
            )

            # Apply configuration
            result = subprocess.run(
                ['terraform', 'apply', '-auto-approve', f'-target=module.{instance_id}'],
                cwd=self.terraform_dir,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                # Parse output for IP
                ip_address = self._parse_terraform_ip(result.stdout)

                instance = CloudInstance(
                    instance_id=instance_id,
                    provider=self.default_provider,
                    instance_type=instance_type,
                    ip_address=ip_address,
                    region=region,
                    status=InstanceStatus.RUNNING,
                    created_at=time.time(),
                    cost_per_hour=self._get_instance_cost(instance_type),
                    purpose=purpose,
                    tags={'prometheus': 'true', 'purpose': purpose}
                )

                return instance
            else:
                self.logger.error(f"Terraform apply failed: {result.stderr}")
                return None

        except Exception as e:
            self.logger.error(f"Terraform error: {e}")
            return None

    def terminate_instance(self, instance_id: str) -> bool:
        """
        Terminate a cloud instance.

        Args:
            instance_id: Instance ID

        Returns:
            True if successful
        """
        if instance_id not in self.instances:
            self.logger.error(f"Instance not found: {instance_id}")
            return False

        instance = self.instances[instance_id]

        self.logger.info(f"Terminating instance: {instance_id}")

        if self.axiom_available:
            success = self._terminate_via_axiom(instance_id)
        else:
            success = self._terminate_via_terraform(instance_id)

        if success:
            # Calculate final cost
            runtime_hours = (time.time() - instance.created_at) / 3600
            cost = runtime_hours * instance.cost_per_hour
            self.total_cost += cost
            self.stats['total_cost_usd'] += cost

            del self.instances[instance_id]
            self.stats['total_terminated'] += 1
            self.stats['current_instances'] = len(self.instances)

            self.logger.info(f"✓ Instance terminated: {instance_id} (cost: ${cost:.2f})")
            return True

        return False

    def _terminate_via_axiom(self, instance_id: str) -> bool:
        """Terminate instance via Axiom."""
        try:
            result = subprocess.run(
                ['axiom-rm', instance_id, '-f'],
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Axiom termination error: {e}")
            return False

    def _terminate_via_terraform(self, instance_id: str) -> bool:
        """Terminate instance via Terraform."""
        try:
            result = subprocess.run(
                ['terraform', 'destroy', '-auto-approve', f'-target=module.{instance_id}'],
                cwd=self.terraform_dir,
                capture_output=True,
                timeout=60
            )
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Terraform termination error: {e}")
            return False

    def auto_scale(self, current_load: float) -> int:
        """
        Automatically scale infrastructure based on load.

        Args:
            current_load: Current load (0.0 to 1.0)

        Returns:
            Number of instances after scaling
        """
        # Check cooldown
        if time.time() - self.last_scaling_action < self.scaling_config.cooldown_seconds:
            return len(self.instances)

        current_instances = len(self.instances)

        # Determine scaling action
        if current_load > self.scaling_config.scale_up_threshold:
            # Scale up
            target = min(
                current_instances + 5,
                self.scaling_config.max_instances
            )

            if target > current_instances:
                self.logger.info(f"Scaling UP: {current_instances} -> {target} (load: {current_load:.1%})")
                self._scale_up(target - current_instances)
                self.stats['scale_up_events'] += 1
                self.last_scaling_action = time.time()

        elif current_load < self.scaling_config.scale_down_threshold:
            # Scale down
            target = max(
                current_instances - 2,
                self.scaling_config.min_instances
            )

            if target < current_instances:
                self.logger.info(f"Scaling DOWN: {current_instances} -> {target} (load: {current_load:.1%})")
                self._scale_down(current_instances - target)
                self.stats['scale_down_events'] += 1
                self.last_scaling_action = time.time()

        return len(self.instances)

    def _scale_up(self, count: int):
        """Scale up by provisioning instances."""
        for i in range(count):
            self.provision_instance(purpose='scanner')
            time.sleep(2)  # Small delay between provisions

    def _scale_down(self, count: int):
        """Scale down by terminating instances."""
        # Terminate oldest instances
        sorted_instances = sorted(
            self.instances.items(),
            key=lambda x: x[1].created_at
        )

        for i in range(min(count, len(sorted_instances))):
            instance_id = sorted_instances[i][0]
            self.terminate_instance(instance_id)

    def provision_fleet(self, count: int, purpose: str = 'scanner') -> List[CloudInstance]:
        """
        Provision a fleet of instances.

        Args:
            count: Number of instances
            purpose: Purpose

        Returns:
            List of provisioned instances
        """
        self.logger.info(f"Provisioning fleet of {count} instances for {purpose}")

        instances = []
        for i in range(count):
            instance = self.provision_instance(purpose=purpose)
            if instance:
                instances.append(instance)
            time.sleep(1)  # Small delay

        self.logger.info(f"Fleet provisioned: {len(instances)}/{count} instances")
        return instances

    def terminate_all(self):
        """Terminate all instances."""
        self.logger.warning(f"Terminating all {len(self.instances)} instances...")

        for instance_id in list(self.instances.keys()):
            self.terminate_instance(instance_id)

        self.logger.info("All instances terminated")

    def get_instance_ips(self, purpose: Optional[str] = None) -> List[str]:
        """Get IPs of running instances."""
        ips = []
        for instance in self.instances.values():
            if purpose is None or instance.purpose == purpose:
                if instance.ip_address:
                    ips.append(instance.ip_address)
        return ips

    def _generate_terraform_config(self,
                                   instance_id: str,
                                   instance_type: str,
                                   region: str) -> str:
        """Generate Terraform configuration."""
        return f"""
module "{instance_id}" {{
  source = "./modules/digitalocean_droplet"

  name   = "{instance_id}"
  size   = "{instance_type}"
  region = "{region}"

  tags = [
    "prometheus",
    "autonomous"
  ]
}}

output "{instance_id}_ip" {{
  value = module.{instance_id}.ipv4_address
}}
"""

    def _parse_axiom_ip(self, output: str) -> Optional[str]:
        """Parse IP address from Axiom output."""
        # Simple parser - in real implementation, parse actual Axiom output
        import re
        match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', output)
        return match.group(0) if match else None

    def _parse_terraform_ip(self, output: str) -> Optional[str]:
        """Parse IP address from Terraform output."""
        import re
        match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', output)
        return match.group(0) if match else None

    def _get_instance_cost(self, instance_type: str) -> float:
        """Get hourly cost for instance type."""
        # Digital Ocean pricing (as of 2025)
        pricing = {
            's-1vcpu-1gb': 0.00744,     # $5/month
            's-1vcpu-2gb': 0.0119,      # $8/month
            's-2vcpu-2gb': 0.0223,      # $15/month
            's-2vcpu-4gb': 0.0298,      # $20/month
            's-4vcpu-8gb': 0.0595,      # $40/month
            'c-2': 0.0595,              # CPU-optimized
            'c-4': 0.119,
        }
        return pricing.get(instance_type, 0.02)  # Default ~$15/month

    def get_statistics(self) -> Dict:
        """Get scaling statistics."""
        return {
            **self.stats,
            'current_instances': len(self.instances),
            'axiom_available': self.axiom_available,
            'min_instances': self.scaling_config.min_instances,
            'max_instances': self.scaling_config.max_instances,
            'estimated_hourly_cost': sum(i.cost_per_hour for i in self.instances.values())
        }

    def get_cost_report(self) -> str:
        """Generate cost report."""
        report = []
        report.append("="*80)
        report.append("INFRASTRUCTURE COST REPORT")
        report.append("="*80)
        report.append(f"Total Instances Provisioned: {self.stats['total_provisioned']}")
        report.append(f"Total Instances Terminated: {self.stats['total_terminated']}")
        report.append(f"Current Running Instances: {len(self.instances)}")
        report.append(f"Total Cost: ${self.stats['total_cost_usd']:.2f}")

        current_hourly = sum(i.cost_per_hour for i in self.instances.values())
        report.append(f"Current Hourly Rate: ${current_hourly:.4f}/hour")
        report.append(f"Estimated Daily Cost: ${current_hourly * 24:.2f}/day")

        if self.instances:
            report.append("\nActive Instances:")
            for instance in self.instances.values():
                runtime_hours = (time.time() - instance.created_at) / 3600
                instance_cost = runtime_hours * instance.cost_per_hour
                report.append(f"  {instance.instance_id}: {instance.ip_address} - "
                            f"${instance_cost:.2f} ({runtime_hours:.1f}h)")

        return "\n".join(report)


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Initialize autoscaler
    scaler = InfrastructureAutoscaler()

    print("Infrastructure Autoscaler initialized\n")
    print(f"Axiom available: {scaler.axiom_available}\n")

    # Provision a single instance (simulation)
    print("Provisioning test instance...")
    # instance = scaler.provision_instance(purpose='scanner')
    # print(f"Instance: {instance}")

    # Simulate auto-scaling
    print("\nSimulating auto-scaling...")
    current_load = 0.9  # 90% load
    print(f"Current load: {current_load:.1%}")
    instances_after = scaler.auto_scale(current_load)
    print(f"Instances after scaling: {instances_after}")

    # Show statistics
    print("\nStatistics:")
    print(json.dumps(scaler.get_statistics(), indent=2))

    # Show cost report
    print("\n" + scaler.get_cost_report())
