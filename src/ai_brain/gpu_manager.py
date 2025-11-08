"""
GPU RESOURCE MANAGER
Manages GTX 1080 (CUDA:0) + GTX 1650 (CUDA:1)
"""

import logging
from typing import Dict, List, Optional


class GPUManager:
    """
    GPU Resource Manager for dual-GPU setup.

    Hardware:
    - CUDA:0 → GTX 1080 (8GB VRAM)
    - CUDA:1 → GTX 1650 (4GB VRAM)
    """

    def __init__(self):
        self.logger = logging.getLogger("GPUManager")
        self.logger.setLevel(logging.INFO)

        self.gpus = {
            "cuda:0": {"name": "GTX 1080", "memory": "8GB", "allocated": False},
            "cuda:1": {"name": "GTX 1650", "memory": "4GB", "allocated": False}
        }

        self._check_gpu_availability()

    def _check_gpu_availability(self):
        """Check if CUDA GPUs are available"""
        try:
            import torch
            if torch.cuda.is_available():
                gpu_count = torch.cuda.device_count()
                self.logger.info(f"🎮 {gpu_count} CUDA GPU(s) available")

                for i in range(min(gpu_count, 2)):
                    name = torch.cuda.get_device_name(i)
                    memory = torch.cuda.get_device_properties(i).total_memory / 1024**3
                    self.logger.info(f"  CUDA:{i} → {name} ({memory:.1f}GB)")

                self.cuda_available = True
            else:
                self.logger.warning("⚠️  CUDA not available - running in CPU mode")
                self.cuda_available = False

        except ImportError:
            self.logger.warning("⚠️  PyTorch not installed")
            self.cuda_available = False

    def allocate_gpu(self, preference: Optional[str] = None) -> str:
        """
        Allocate available GPU.

        Args:
            preference: Preferred GPU device (cuda:0 or cuda:1)

        Returns:
            Allocated GPU device string
        """
        if preference and not self.gpus[preference]["allocated"]:
            self.gpus[preference]["allocated"] = True
            self.logger.info(f"✅ Allocated {preference} ({self.gpus[preference]['name']})")
            return preference

        # Allocate first available
        for device, info in self.gpus.items():
            if not info["allocated"]:
                info["allocated"] = True
                self.logger.info(f"✅ Allocated {device} ({info['name']})")
                return device

        self.logger.warning("⚠️  No GPU available, using CPU")
        return "cpu"

    def release_gpu(self, device: str):
        """Release GPU allocation"""
        if device in self.gpus:
            self.gpus[device]["allocated"] = False
            self.logger.info(f"🗑️  Released {device}")

    def get_gpu_stats(self) -> Dict:
        """Get GPU statistics"""
        try:
            import torch
            if not torch.cuda.is_available():
                return {"cuda_available": False}

            stats = {"cuda_available": True, "devices": {}}

            for i in range(min(torch.cuda.device_count(), 2)):
                device = f"cuda:{i}"
                stats["devices"][device] = {
                    "name": torch.cuda.get_device_name(i),
                    "total_memory_gb": torch.cuda.get_device_properties(i).total_memory / 1024**3,
                    "allocated_memory_gb": torch.cuda.memory_allocated(i) / 1024**3,
                    "cached_memory_gb": torch.cuda.memory_reserved(i) / 1024**3,
                    "utilization": self.gpus.get(device, {}).get("allocated", False)
                }

            return stats

        except ImportError:
            return {"cuda_available": False, "error": "PyTorch not installed"}

    def clear_cache(self):
        """Clear GPU cache"""
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
                self.logger.info("🗑️  GPU cache cleared")
        except ImportError:
            pass


if __name__ == "__main__":
    print("🎮 GPU MANAGER TEST")
    print("=" * 60)

    manager = GPUManager()

    print("\n📊 GPU Statistics:")
    stats = manager.get_gpu_stats()
    for device, info in stats.get("devices", {}).items():
        print(f"\n{device}: {info['name']}")
        print(f"  Total Memory: {info['total_memory_gb']:.2f} GB")
        print(f"  Allocated: {info['allocated_memory_gb']:.2f} GB")
        print(f"  Cached: {info['cached_memory_gb']:.2f} GB")

    print("\n✅ GPU Manager test complete")
