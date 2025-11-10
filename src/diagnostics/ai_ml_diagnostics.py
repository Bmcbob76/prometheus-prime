"""
PROMETHEUS PRIME - AI/ML DIAGNOSTICS MODULE

⚠️ AUTHORIZED USE ONLY - CONTROLLED LAB ENVIRONMENT ⚠️

AI model health monitoring, inference performance, GPU utilization tracking.
Comprehensive AI/ML system diagnostics and optimization recommendations.
"""

import os
import sys
import platform
import subprocess
import logging
import time
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import psutil

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None

try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    tf = None

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None


class AIMLDiagnostics:
    """
    Comprehensive AI/ML diagnostics system.

    Features:
    - GPU detection and utilization
    - CUDA/cuDNN verification
    - Model health checks
    - Inference performance benchmarks
    - Memory profiling
    - Framework compatibility
    - Quantization verification
    - Multi-GPU load balancing
    """

    def __init__(self):
        self.logger = logging.getLogger("AIMLDiagnostics")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "hardware": {},
            "frameworks": {},
            "gpu": {},
            "models": {},
            "performance": {},
            "memory": {},
            "health_score": 0
        }

    def run_full_diagnostics(self) -> Dict:
        """Run complete AI/ML diagnostics suite."""
        self.logger.info("Starting AI/ML diagnostics...")

        # Hardware detection
        self.detect_gpus()
        self.check_cuda_support()
        self.check_cpu_capabilities()

        # Framework checks
        self.check_pytorch()
        self.check_tensorflow()
        self.check_framework_compatibility()

        # GPU monitoring
        self.monitor_gpu_utilization()
        self.check_gpu_memory()
        self.check_multi_gpu_setup()

        # Performance benchmarks
        self.benchmark_inference()
        self.benchmark_memory_bandwidth()

        # Model checks
        self.check_model_quantization()
        self.verify_model_formats()

        # Calculate health score
        self.calculate_health_score()

        self.logger.info("AI/ML diagnostics complete")
        return self.results

    def detect_gpus(self) -> Dict:
        """Detect available GPUs."""
        self.logger.info("Detecting GPUs...")

        results = {
            "gpus_detected": [],
            "total_gpus": 0,
            "primary_gpu": None
        }

        # Try NVIDIA SMI
        try:
            output = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=index,name,memory.total,driver_version",
                 "--format=csv,noheader,nounits"],
                stderr=subprocess.DEVNULL
            ).decode()

            for line in output.strip().split('\n'):
                if line.strip():
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 4:
                        gpu_info = {
                            "index": int(parts[0]),
                            "name": parts[1],
                            "memory_mb": int(parts[2]),
                            "driver_version": parts[3]
                        }
                        results["gpus_detected"].append(gpu_info)

            results["total_gpus"] = len(results["gpus_detected"])
            if results["gpus_detected"]:
                results["primary_gpu"] = results["gpus_detected"][0]["name"]

        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.info("NVIDIA GPU not detected or nvidia-smi not available")

        # Try PyTorch detection
        if TORCH_AVAILABLE and torch.cuda.is_available():
            if not results["gpus_detected"]:
                for i in range(torch.cuda.device_count()):
                    gpu_info = {
                        "index": i,
                        "name": torch.cuda.get_device_name(i),
                        "memory_mb": torch.cuda.get_device_properties(i).total_memory // (1024**2),
                        "compute_capability": f"{torch.cuda.get_device_capability(i)[0]}.{torch.cuda.get_device_capability(i)[1]}"
                    }
                    results["gpus_detected"].append(gpu_info)

                results["total_gpus"] = len(results["gpus_detected"])
                if results["gpus_detected"]:
                    results["primary_gpu"] = results["gpus_detected"][0]["name"]

        self.results["hardware"]["gpus"] = results
        return results

    def check_cuda_support(self) -> Dict:
        """Check CUDA and cuDNN support."""
        self.logger.info("Checking CUDA support...")

        results = {
            "cuda_available": False,
            "cuda_version": None,
            "cudnn_version": None,
            "pytorch_cuda": False,
            "tensorflow_cuda": False
        }

        # Check PyTorch CUDA
        if TORCH_AVAILABLE:
            results["pytorch_cuda"] = torch.cuda.is_available()
            if results["pytorch_cuda"]:
                results["cuda_available"] = True
                results["cuda_version"] = torch.version.cuda
                try:
                    results["cudnn_version"] = torch.backends.cudnn.version()
                except:
                    pass

        # Check TensorFlow CUDA
        if TF_AVAILABLE:
            gpus = tf.config.list_physical_devices('GPU')
            results["tensorflow_cuda"] = len(gpus) > 0
            if results["tensorflow_cuda"]:
                results["cuda_available"] = True
                # TF CUDA version
                try:
                    results["cuda_version"] = tf.sysconfig.get_build_info()["cuda_version"]
                    results["cudnn_version"] = tf.sysconfig.get_build_info()["cudnn_version"]
                except:
                    pass

        # Check NVCC
        try:
            output = subprocess.check_output(["nvcc", "--version"], stderr=subprocess.DEVNULL).decode()
            for line in output.split('\n'):
                if "release" in line.lower():
                    results["nvcc_version"] = line.strip()
        except:
            pass

        self.results["hardware"]["cuda"] = results
        return results

    def check_cpu_capabilities(self) -> Dict:
        """Check CPU capabilities for AI/ML workloads."""
        self.logger.info("Checking CPU capabilities...")

        results = {
            "cpu_model": platform.processor(),
            "cores_physical": psutil.cpu_count(logical=False),
            "cores_logical": psutil.cpu_count(logical=True),
            "cpu_freq_mhz": None,
            "features": []
        }

        # Get CPU frequency
        try:
            freq = psutil.cpu_freq()
            if freq:
                results["cpu_freq_mhz"] = freq.max if freq.max > 0 else freq.current
        except:
            pass

        # Check CPU features (Linux only)
        if platform.system() == "Linux":
            try:
                with open("/proc/cpuinfo", 'r') as f:
                    cpuinfo = f.read()
                    if "avx2" in cpuinfo:
                        results["features"].append("AVX2")
                    if "avx512" in cpuinfo:
                        results["features"].append("AVX512")
                    if "sse4" in cpuinfo:
                        results["features"].append("SSE4")
            except:
                pass

        self.results["hardware"]["cpu"] = results
        return results

    def check_pytorch(self) -> Dict:
        """Check PyTorch installation and capabilities."""
        self.logger.info("Checking PyTorch...")

        results = {
            "installed": TORCH_AVAILABLE,
            "version": None,
            "cuda_enabled": False,
            "cuda_version": None,
            "cudnn_enabled": False,
            "devices": []
        }

        if TORCH_AVAILABLE:
            results["version"] = torch.__version__
            results["cuda_enabled"] = torch.cuda.is_available()

            if results["cuda_enabled"]:
                results["cuda_version"] = torch.version.cuda
                results["cudnn_enabled"] = torch.backends.cudnn.enabled
                results["cudnn_version"] = torch.backends.cudnn.version()

                # List devices
                for i in range(torch.cuda.device_count()):
                    results["devices"].append({
                        "device_id": i,
                        "name": torch.cuda.get_device_name(i),
                        "capability": f"{torch.cuda.get_device_capability(i)[0]}.{torch.cuda.get_device_capability(i)[1]}"
                    })

        self.results["frameworks"]["pytorch"] = results
        return results

    def check_tensorflow(self) -> Dict:
        """Check TensorFlow installation and capabilities."""
        self.logger.info("Checking TensorFlow...")

        results = {
            "installed": TF_AVAILABLE,
            "version": None,
            "cuda_enabled": False,
            "devices": []
        }

        if TF_AVAILABLE:
            results["version"] = tf.__version__

            # Check for GPU devices
            gpus = tf.config.list_physical_devices('GPU')
            results["cuda_enabled"] = len(gpus) > 0

            # List all devices
            devices = tf.config.list_physical_devices()
            for device in devices:
                results["devices"].append({
                    "name": device.name,
                    "type": device.device_type
                })

        self.results["frameworks"]["tensorflow"] = results
        return results

    def check_framework_compatibility(self) -> Dict:
        """Check compatibility between frameworks."""
        self.logger.info("Checking framework compatibility...")

        results = {
            "pytorch_tf_compatible": False,
            "numpy_available": NUMPY_AVAILABLE,
            "issues": []
        }

        if TORCH_AVAILABLE and TF_AVAILABLE:
            # Check if both can use CUDA
            pytorch_cuda = self.results["frameworks"]["pytorch"]["cuda_enabled"]
            tf_cuda = self.results["frameworks"]["tensorflow"]["cuda_enabled"]

            if pytorch_cuda != tf_cuda:
                results["issues"].append({
                    "issue": "PyTorch and TensorFlow have different CUDA availability",
                    "severity": "MEDIUM"
                })
            else:
                results["pytorch_tf_compatible"] = True

        self.results["frameworks"]["compatibility"] = results
        return results

    def monitor_gpu_utilization(self) -> Dict:
        """Monitor current GPU utilization."""
        self.logger.info("Monitoring GPU utilization...")

        results = {
            "gpus": [],
            "timestamp": datetime.now().isoformat()
        }

        try:
            output = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=index,utilization.gpu,utilization.memory,temperature.gpu,power.draw",
                 "--format=csv,noheader,nounits"],
                stderr=subprocess.DEVNULL
            ).decode()

            for line in output.strip().split('\n'):
                if line.strip():
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 5:
                        gpu_util = {
                            "index": int(parts[0]),
                            "gpu_utilization_pct": int(parts[1]),
                            "memory_utilization_pct": int(parts[2]),
                            "temperature_c": int(parts[3]),
                            "power_draw_w": float(parts[4])
                        }
                        results["gpus"].append(gpu_util)

        except (subprocess.CalledProcessError, FileNotFoundError):
            results["error"] = "Unable to query GPU utilization"

        self.results["gpu"]["utilization"] = results
        return results

    def check_gpu_memory(self) -> Dict:
        """Check GPU memory status."""
        self.logger.info("Checking GPU memory...")

        results = {
            "gpus": []
        }

        if TORCH_AVAILABLE and torch.cuda.is_available():
            for i in range(torch.cuda.device_count()):
                memory_allocated = torch.cuda.memory_allocated(i) / (1024**3)  # GB
                memory_reserved = torch.cuda.memory_reserved(i) / (1024**3)  # GB
                memory_total = torch.cuda.get_device_properties(i).total_memory / (1024**3)  # GB

                gpu_mem = {
                    "device_id": i,
                    "allocated_gb": round(memory_allocated, 2),
                    "reserved_gb": round(memory_reserved, 2),
                    "total_gb": round(memory_total, 2),
                    "free_gb": round(memory_total - memory_reserved, 2),
                    "utilization_pct": round((memory_reserved / memory_total) * 100, 1)
                }
                results["gpus"].append(gpu_mem)

        self.results["gpu"]["memory"] = results
        return results

    def check_multi_gpu_setup(self) -> Dict:
        """Check multi-GPU configuration."""
        self.logger.info("Checking multi-GPU setup...")

        results = {
            "multi_gpu_available": False,
            "gpu_count": 0,
            "distributed_available": False,
            "nccl_available": False
        }

        if TORCH_AVAILABLE and torch.cuda.is_available():
            results["gpu_count"] = torch.cuda.device_count()
            results["multi_gpu_available"] = results["gpu_count"] > 1
            results["distributed_available"] = torch.distributed.is_available()

            if results["distributed_available"]:
                try:
                    results["nccl_available"] = torch.distributed.is_nccl_available()
                except:
                    pass

        self.results["gpu"]["multi_gpu"] = results
        return results

    def benchmark_inference(self) -> Dict:
        """Benchmark inference performance."""
        self.logger.info("Benchmarking inference performance...")

        results = {
            "cpu_inference_ms": None,
            "gpu_inference_ms": None,
            "speedup": None
        }

        if not TORCH_AVAILABLE or not NUMPY_AVAILABLE:
            results["error"] = "PyTorch or NumPy not available"
            self.results["performance"]["inference"] = results
            return results

        # Create dummy model and data
        batch_size = 32
        input_size = 512

        model = torch.nn.Sequential(
            torch.nn.Linear(input_size, 256),
            torch.nn.ReLU(),
            torch.nn.Linear(256, 128),
            torch.nn.ReLU(),
            torch.nn.Linear(128, 10)
        )

        dummy_input = torch.randn(batch_size, input_size)

        # CPU benchmark
        model.eval()
        with torch.no_grad():
            # Warmup
            for _ in range(10):
                _ = model(dummy_input)

            # Benchmark
            start_time = time.time()
            iterations = 100
            for _ in range(iterations):
                _ = model(dummy_input)
            cpu_time = (time.time() - start_time) / iterations * 1000  # ms

        results["cpu_inference_ms"] = round(cpu_time, 2)

        # GPU benchmark
        if torch.cuda.is_available():
            model_gpu = model.cuda()
            dummy_input_gpu = dummy_input.cuda()

            with torch.no_grad():
                # Warmup
                for _ in range(10):
                    _ = model_gpu(dummy_input_gpu)
                torch.cuda.synchronize()

                # Benchmark
                start_time = time.time()
                for _ in range(iterations):
                    _ = model_gpu(dummy_input_gpu)
                torch.cuda.synchronize()
                gpu_time = (time.time() - start_time) / iterations * 1000  # ms

            results["gpu_inference_ms"] = round(gpu_time, 2)
            results["speedup"] = round(cpu_time / gpu_time, 2)

        self.results["performance"]["inference"] = results
        return results

    def benchmark_memory_bandwidth(self) -> Dict:
        """Benchmark memory bandwidth."""
        self.logger.info("Benchmarking memory bandwidth...")

        results = {
            "cpu_to_gpu_gbps": None,
            "gpu_to_cpu_gbps": None
        }

        if not TORCH_AVAILABLE or not torch.cuda.is_available():
            results["error"] = "PyTorch with CUDA not available"
            self.results["performance"]["memory_bandwidth"] = results
            return results

        # Test data transfer
        size_mb = 100
        tensor_size = (size_mb * 1024 * 1024) // 4  # Float32
        tensor_cpu = torch.randn(tensor_size)

        # CPU to GPU
        iterations = 10
        start_time = time.time()
        for _ in range(iterations):
            tensor_gpu = tensor_cpu.cuda()
            torch.cuda.synchronize()
        cpu_to_gpu_time = (time.time() - start_time) / iterations

        cpu_to_gpu_gbps = (size_mb / 1024) / cpu_to_gpu_time
        results["cpu_to_gpu_gbps"] = round(cpu_to_gpu_gbps, 2)

        # GPU to CPU
        start_time = time.time()
        for _ in range(iterations):
            tensor_back = tensor_gpu.cpu()
            torch.cuda.synchronize()
        gpu_to_cpu_time = (time.time() - start_time) / iterations

        gpu_to_cpu_gbps = (size_mb / 1024) / gpu_to_cpu_time
        results["gpu_to_cpu_gbps"] = round(gpu_to_cpu_gbps, 2)

        self.results["performance"]["memory_bandwidth"] = results
        return results

    def check_model_quantization(self) -> Dict:
        """Check model quantization support."""
        self.logger.info("Checking quantization support...")

        results = {
            "pytorch_quantization": False,
            "tf_quantization": False,
            "int8_supported": False,
            "int4_supported": False
        }

        if TORCH_AVAILABLE:
            results["pytorch_quantization"] = hasattr(torch, 'quantization')

            if torch.cuda.is_available():
                # Check for INT8 support (compute capability >= 6.1)
                capability = torch.cuda.get_device_capability(0)
                if capability[0] >= 6 and capability[1] >= 1:
                    results["int8_supported"] = True

                # Check for INT4 support (compute capability >= 7.5)
                if capability[0] >= 7 and capability[1] >= 5:
                    results["int4_supported"] = True

        if TF_AVAILABLE:
            try:
                import tensorflow.lite as tflite
                results["tf_quantization"] = True
            except:
                pass

        self.results["models"]["quantization"] = results
        return results

    def verify_model_formats(self) -> Dict:
        """Verify supported model formats."""
        self.logger.info("Verifying model formats...")

        results = {
            "pytorch_formats": [],
            "tensorflow_formats": [],
            "onnx_available": False
        }

        if TORCH_AVAILABLE:
            results["pytorch_formats"].extend(["pt", "pth", "bin"])

        if TF_AVAILABLE:
            results["tensorflow_formats"].extend(["pb", "h5", "saved_model"])

        # Check ONNX
        try:
            import onnx
            results["onnx_available"] = True
            results["onnx_version"] = onnx.__version__
        except ImportError:
            pass

        self.results["models"]["formats"] = results
        return results

    def calculate_health_score(self) -> int:
        """Calculate overall AI/ML health score (0-100)."""
        score = 0

        # GPU availability (30 points)
        if self.results.get("hardware", {}).get("gpus", {}).get("total_gpus", 0) > 0:
            score += 30
        else:
            score += 10  # CPU only

        # CUDA support (20 points)
        if self.results.get("hardware", {}).get("cuda", {}).get("cuda_available", False):
            score += 20

        # Framework availability (20 points)
        if TORCH_AVAILABLE:
            score += 10
        if TF_AVAILABLE:
            score += 10

        # Performance (20 points)
        if "inference" in self.results.get("performance", {}):
            speedup = self.results["performance"]["inference"].get("speedup", 0)
            if speedup and speedup > 10:
                score += 20
            elif speedup and speedup > 5:
                score += 15
            elif speedup and speedup > 2:
                score += 10
            else:
                score += 5

        # Multi-GPU support (10 points)
        if self.results.get("gpu", {}).get("multi_gpu", {}).get("multi_gpu_available", False):
            score += 10

        self.results["health_score"] = int(score)
        return int(score)

    def get_summary(self) -> Dict:
        """Get AI/ML diagnostics summary."""
        gpu_count = self.results.get("hardware", {}).get("gpus", {}).get("total_gpus", 0)
        cuda_available = self.results.get("hardware", {}).get("cuda", {}).get("cuda_available", False)

        return {
            "timestamp": self.results["timestamp"],
            "health_score": self.results["health_score"],
            "hardware": {
                "gpu_count": gpu_count,
                "primary_gpu": self.results.get("hardware", {}).get("gpus", {}).get("primary_gpu", "None"),
                "cuda_available": cuda_available,
                "cuda_version": self.results.get("hardware", {}).get("cuda", {}).get("cuda_version", "N/A")
            },
            "frameworks": {
                "pytorch": TORCH_AVAILABLE,
                "tensorflow": TF_AVAILABLE,
                "pytorch_version": self.results.get("frameworks", {}).get("pytorch", {}).get("version", "N/A"),
                "tensorflow_version": self.results.get("frameworks", {}).get("tensorflow", {}).get("version", "N/A")
            },
            "performance": {
                "gpu_speedup": self.results.get("performance", {}).get("inference", {}).get("speedup", "N/A"),
                "cpu_inference_ms": self.results.get("performance", {}).get("inference", {}).get("cpu_inference_ms", "N/A"),
                "gpu_inference_ms": self.results.get("performance", {}).get("inference", {}).get("gpu_inference_ms", "N/A")
            },
            "recommendations": self._generate_recommendations()
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate AI/ML optimization recommendations."""
        recommendations = []

        score = self.results.get("health_score", 0)

        # Overall health
        if score < 50:
            recommendations.append("CRITICAL: AI/ML capabilities are limited. Consider GPU upgrade.")
        elif score < 70:
            recommendations.append("WARNING: AI/ML performance could be improved.")

        # GPU recommendations
        gpu_count = self.results.get("hardware", {}).get("gpus", {}).get("total_gpus", 0)
        if gpu_count == 0:
            recommendations.append("No GPU detected. Install NVIDIA GPU for 10-100x speedup.")
        elif gpu_count == 1:
            recommendations.append("Single GPU detected. Consider multi-GPU setup for larger models.")

        # CUDA recommendations
        if not self.results.get("hardware", {}).get("cuda", {}).get("cuda_available", False):
            recommendations.append("CUDA not available. Install CUDA Toolkit and compatible drivers.")

        # Framework recommendations
        if not TORCH_AVAILABLE and not TF_AVAILABLE:
            recommendations.append("No AI frameworks detected. Install PyTorch or TensorFlow.")

        # Performance recommendations
        if "inference" in self.results.get("performance", {}):
            speedup = self.results["performance"]["inference"].get("speedup", 0)
            if speedup and speedup < 5:
                recommendations.append("Low GPU speedup detected. Check GPU memory and batch size optimization.")

        # Memory recommendations
        if "memory" in self.results.get("gpu", {}):
            for gpu in self.results["gpu"]["memory"].get("gpus", []):
                if gpu.get("utilization_pct", 0) > 90:
                    recommendations.append(f"GPU {gpu['device_id']} memory >90%. Consider model quantization.")

        if not recommendations:
            recommendations.append("AI/ML system is optimally configured.")

        return recommendations[:5]  # Top 5 recommendations


if __name__ == "__main__":
    # Test AI/ML diagnostics
    diagnostics = AIMLDiagnostics()
    results = diagnostics.run_full_diagnostics()
    summary = diagnostics.get_summary()

    print("\n" + "="*60)
    print("PROMETHEUS PRIME - AI/ML DIAGNOSTICS")
    print("="*60)
    print(json.dumps(summary, indent=2))
