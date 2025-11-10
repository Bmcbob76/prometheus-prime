#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║     OMEGA SENSORY SYSTEM - COMPLETE INTEGRATION                  ║
║     Voice, Vision, Hearing, OCR, CPU, Internet Sensors          ║
╚══════════════════════════════════════════════════════════════════╝

6 INTEGRATED SENSORS:
1. Voice - Speech to text processing
2. Vision - Image analysis and recognition
3. Hearing - Audio monitoring and processing
4. OCR - Text extraction from images
5. CPU - Performance monitoring
6. Internet - Network activity tracking
"""

import logging
import time
import psutil
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json

# Try imports with fallbacks
try:
    import speech_recognition as sr
    SPEECH_AVAILABLE = True
except ImportError:
    SPEECH_AVAILABLE = False
    logging.warning("speech_recognition not available")

try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    logging.warning("PIL/pytesseract not available")

try:
    import cv2
    VISION_AVAILABLE = True
except ImportError:
    VISION_AVAILABLE = False
    logging.warning("opencv not available")

try:
    import sounddevice as sd
    import numpy as np
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False
    logging.warning("sounddevice not available")

# ══════════════════════════════════════════════════════════════════
# SENSOR TYPES
# ══════════════════════════════════════════════════════════════════

class SensorType(Enum):
    """6 sensor types"""
    VOICE = "voice"
    VISION = "vision"
    HEARING = "hearing"
    OCR = "ocr"
    CPU = "cpu"
    INTERNET = "internet"

class SensorState(Enum):
    """Sensor operational states"""
    INACTIVE = "inactive"
    ACTIVE = "active"
    PROCESSING = "processing"
    ERROR = "error"

# ══════════════════════════════════════════════════════════════════
# SENSOR DATA
# ══════════════════════════════════════════════════════════════════

@dataclass
class SensorData:
    """Sensor reading data"""
    sensor_type: SensorType
    timestamp: float
    data: Any
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

# ══════════════════════════════════════════════════════════════════
# VOICE SENSOR
# ══════════════════════════════════════════════════════════════════

class VoiceSensor:
    """Speech to text processing"""
    
    def __init__(self):
        self.active = False
        self.recognizer = sr.Recognizer() if SPEECH_AVAILABLE else None
        self.callbacks: List[Callable] = []
        
        logging.info("🎤 Voice Sensor initialized")
    
    def start(self):
        """Start voice monitoring"""
        if not SPEECH_AVAILABLE:
            logging.warning("Voice sensor unavailable - missing speech_recognition")
            return False
        
        self.active = True
        logging.info("✅ Voice sensor ACTIVE")
        return True
    
    def stop(self):
        """Stop voice monitoring"""
        self.active = False
        logging.info("🛑 Voice sensor stopped")
    
    def listen(self, duration: float = 5.0) -> Optional[str]:
        """Listen for speech and convert to text"""
        if not self.active or not SPEECH_AVAILABLE:
            return None
        
        try:
            with sr.Microphone() as source:
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio = self.recognizer.listen(source, timeout=duration)
                text = self.recognizer.recognize_google(audio)
                
                data = SensorData(
                    sensor_type=SensorType.VOICE,
                    timestamp=time.time(),
                    data=text,
                    confidence=0.9
                )
                
                # Trigger callbacks
                for callback in self.callbacks:
                    callback(data)
                
                return text
        except Exception as e:
            logging.error(f"Voice sensor error: {e}")
            return None
    
    def register_callback(self, callback: Callable):
        """Register callback for voice events"""
        self.callbacks.append(callback)

# ══════════════════════════════════════════════════════════════════
# VISION SENSOR
# ══════════════════════════════════════════════════════════════════

class VisionSensor:
    """Image analysis and recognition"""
    
    def __init__(self):
        self.active = False
        self.callbacks: List[Callable] = []
        
        logging.info("👁️ Vision Sensor initialized")
    
    def start(self):
        """Start vision monitoring"""
        if not VISION_AVAILABLE:
            logging.warning("Vision sensor unavailable - missing opencv")
            return False
        
        self.active = True
        logging.info("✅ Vision sensor ACTIVE")
        return True
    
    def stop(self):
        """Stop vision monitoring"""
        self.active = False
        logging.info("🛑 Vision sensor stopped")
    
    def analyze_image(self, image_path: str) -> Optional[Dict[str, Any]]:
        """Analyze image from file"""
        if not self.active or not VISION_AVAILABLE:
            return None
        
        try:
            img = cv2.imread(image_path)
            if img is None:
                return None
            
            # Basic analysis
            height, width = img.shape[:2]
            analysis = {
                "dimensions": {"width": width, "height": height},
                "channels": img.shape[2] if len(img.shape) > 2 else 1,
                "mean_brightness": float(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY).mean())
            }
            
            data = SensorData(
                sensor_type=SensorType.VISION,
                timestamp=time.time(),
                data=analysis,
                metadata={"source": image_path}
            )
            
            for callback in self.callbacks:
                callback(data)
            
            return analysis
        except Exception as e:
            logging.error(f"Vision sensor error: {e}")
            return None
    
    def register_callback(self, callback: Callable):
        """Register callback for vision events"""
        self.callbacks.append(callback)

# ══════════════════════════════════════════════════════════════════
# HEARING SENSOR
# ══════════════════════════════════════════════════════════════════

class HearingSensor:
    """Audio monitoring and processing"""
    
    def __init__(self):
        self.active = False
        self.callbacks: List[Callable] = []
        self.recording = False
        
        logging.info("👂 Hearing Sensor initialized")
    
    def start(self):
        """Start audio monitoring"""
        if not AUDIO_AVAILABLE:
            logging.warning("Hearing sensor unavailable - missing sounddevice")
            return False
        
        self.active = True
        logging.info("✅ Hearing sensor ACTIVE")
        return True
    
    def stop(self):
        """Stop audio monitoring"""
        self.active = False
        self.recording = False
        logging.info("🛑 Hearing sensor stopped")
    
    def get_audio_level(self, duration: float = 1.0) -> float:
        """Get current audio level"""
        if not self.active or not AUDIO_AVAILABLE:
            return 0.0
        
        try:
            samplerate = 44100
            recording = sd.rec(int(duration * samplerate), 
                             samplerate=samplerate, 
                             channels=1)
            sd.wait()
            
            level = float(np.abs(recording).mean())
            
            data = SensorData(
                sensor_type=SensorType.HEARING,
                timestamp=time.time(),
                data={"level": level, "duration": duration}
            )
            
            for callback in self.callbacks:
                callback(data)
            
            return level
        except Exception as e:
            logging.error(f"Hearing sensor error: {e}")
            return 0.0
    
    def register_callback(self, callback: Callable):
        """Register callback for hearing events"""
        self.callbacks.append(callback)

# ══════════════════════════════════════════════════════════════════
# OCR SENSOR
# ══════════════════════════════════════════════════════════════════

class OCRSensor:
    """Text extraction from images"""
    
    def __init__(self):
        self.active = False
        self.callbacks: List[Callable] = []
        
        logging.info("📄 OCR Sensor initialized")
    
    def start(self):
        """Start OCR processing"""
        if not OCR_AVAILABLE:
            logging.warning("OCR sensor unavailable - missing PIL/pytesseract")
            return False
        
        self.active = True
        logging.info("✅ OCR sensor ACTIVE")
        return True
    
    def stop(self):
        """Stop OCR processing"""
        self.active = False
        logging.info("🛑 OCR sensor stopped")
    
    def extract_text(self, image_path: str) -> Optional[str]:
        """Extract text from image"""
        if not self.active or not OCR_AVAILABLE:
            return None
        
        try:
            img = Image.open(image_path)
            text = pytesseract.image_to_string(img)
            
            data = SensorData(
                sensor_type=SensorType.OCR,
                timestamp=time.time(),
                data=text,
                metadata={"source": image_path, "length": len(text)}
            )
            
            for callback in self.callbacks:
                callback(data)
            
            return text
        except Exception as e:
            logging.error(f"OCR sensor error: {e}")
            return None
    
    def register_callback(self, callback: Callable):
        """Register callback for OCR events"""
        self.callbacks.append(callback)

# ══════════════════════════════════════════════════════════════════
# CPU SENSOR
# ══════════════════════════════════════════════════════════════════

class CPUSensor:
    """Performance monitoring"""
    
    def __init__(self):
        self.active = False
        self.callbacks: List[Callable] = []
        self.monitor_thread = None
        self.monitoring = False
        
        logging.info("💻 CPU Sensor initialized")
    
    def start(self):
        """Start CPU monitoring"""
        self.active = True
        self.monitoring = True
        
        # Start background monitoring
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logging.info("✅ CPU sensor ACTIVE")
        return True
    
    def stop(self):
        """Stop CPU monitoring"""
        self.active = False
        self.monitoring = False
        logging.info("🛑 CPU sensor stopped")
    
    def get_metrics(self) -> Dict[str, float]:
        """Get current CPU metrics"""
        try:
            metrics = {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "cpu_count": psutil.cpu_count()
            }
            
            data = SensorData(
                sensor_type=SensorType.CPU,
                timestamp=time.time(),
                data=metrics
            )
            
            for callback in self.callbacks:
                callback(data)
            
            return metrics
        except Exception as e:
            logging.error(f"CPU sensor error: {e}")
            return {}
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self.monitoring:
            self.get_metrics()
            time.sleep(5.0)  # Check every 5 seconds
    
    def register_callback(self, callback: Callable):
        """Register callback for CPU events"""
        self.callbacks.append(callback)

# ══════════════════════════════════════════════════════════════════
# INTERNET SENSOR
# ══════════════════════════════════════════════════════════════════

class InternetSensor:
    """Network activity tracking"""
    
    def __init__(self):
        self.active = False
        self.callbacks: List[Callable] = []
        self.baseline_stats = None
        
        logging.info("🌐 Internet Sensor initialized")
    
    def start(self):
        """Start internet monitoring"""
        self.active = True
        self.baseline_stats = psutil.net_io_counters()
        logging.info("✅ Internet sensor ACTIVE")
        return True
    
    def stop(self):
        """Stop internet monitoring"""
        self.active = False
        logging.info("🛑 Internet sensor stopped")
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get current network statistics"""
        if not self.active:
            return {}
        
        try:
            current = psutil.net_io_counters()
            
            stats = {
                "bytes_sent": current.bytes_sent,
                "bytes_recv": current.bytes_recv,
                "packets_sent": current.packets_sent,
                "packets_recv": current.packets_recv,
                "errin": current.errin,
                "errout": current.errout,
                "dropin": current.dropin,
                "dropout": current.dropout
            }
            
            if self.baseline_stats:
                stats["bytes_sent_delta"] = current.bytes_sent - self.baseline_stats.bytes_sent
                stats["bytes_recv_delta"] = current.bytes_recv - self.baseline_stats.bytes_recv
            
            data = SensorData(
                sensor_type=SensorType.INTERNET,
                timestamp=time.time(),
                data=stats
            )
            
            for callback in self.callbacks:
                callback(data)
            
            return stats
        except Exception as e:
            logging.error(f"Internet sensor error: {e}")
            return {}
    
    def register_callback(self, callback: Callable):
        """Register callback for internet events"""
        self.callbacks.append(callback)

# ══════════════════════════════════════════════════════════════════
# UNIFIED SENSORY SYSTEM
# ══════════════════════════════════════════════════════════════════

class OmegaSensorySystem:
    """
    Unified sensory integration for Omega Brain
    Manages all 6 sensors with unified interface
    """
    
    def __init__(self):
        # Initialize all sensors
        self.voice = VoiceSensor()
        self.vision = VisionSensor()
        self.hearing = HearingSensor()
        self.ocr = OCRSensor()
        self.cpu = CPUSensor()
        self.internet = InternetSensor()
        
        self.sensors = {
            SensorType.VOICE: self.voice,
            SensorType.VISION: self.vision,
            SensorType.HEARING: self.hearing,
            SensorType.OCR: self.ocr,
            SensorType.CPU: self.cpu,
            SensorType.INTERNET: self.internet
        }
        
        self.sensor_data_history: List[SensorData] = []
        self.max_history = 1000
        
        logging.info("╔══════════════════════════════════════════════════════════════╗")
        logging.info("║         OMEGA SENSORY SYSTEM INITIALIZED                     ║")
        logging.info("╚══════════════════════════════════════════════════════════════╝")
    
    def start_all(self):
        """Start all available sensors"""
        results = {}
        for sensor_type, sensor in self.sensors.items():
            try:
                success = sensor.start()
                results[sensor_type.value] = success
            except Exception as e:
                logging.error(f"Failed to start {sensor_type.value}: {e}")
                results[sensor_type.value] = False
        
        active_count = sum(1 for v in results.values() if v)
        logging.info(f"✅ {active_count}/6 sensors active")
        return results
    
    def stop_all(self):
        """Stop all sensors"""
        for sensor in self.sensors.values():
            sensor.stop()
        logging.info("🛑 All sensors stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all sensors"""
        return {
            sensor_type.value: {
                "active": sensor.active,
                "available": self._check_sensor_available(sensor_type)
            }
            for sensor_type, sensor in self.sensors.items()
        }
    
    def _check_sensor_available(self, sensor_type: SensorType) -> bool:
        """Check if sensor dependencies are available"""
        availability = {
            SensorType.VOICE: SPEECH_AVAILABLE,
            SensorType.VISION: VISION_AVAILABLE,
            SensorType.HEARING: AUDIO_AVAILABLE,
            SensorType.OCR: OCR_AVAILABLE,
            SensorType.CPU: True,  # Always available (psutil)
            SensorType.INTERNET: True  # Always available (psutil)
        }
        return availability.get(sensor_type, False)
    
    def register_global_callback(self, callback: Callable):
        """Register callback for all sensors"""
        for sensor in self.sensors.values():
            sensor.register_callback(callback)
    
    def log_sensor_data(self, data: SensorData):
        """Log sensor data to history"""
        self.sensor_data_history.append(data)
        if len(self.sensor_data_history) > self.max_history:
            self.sensor_data_history.pop(0)
    
    def get_recent_data(self, sensor_type: Optional[SensorType] = None, 
                       limit: int = 10) -> List[SensorData]:
        """Get recent sensor data"""
        if sensor_type:
            data = [d for d in self.sensor_data_history if d.sensor_type == sensor_type]
        else:
            data = self.sensor_data_history
        
        return data[-limit:]

# ══════════════════════════════════════════════════════════════════
# TESTING
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - SENSORY - %(levelname)s - %(message)s'
    )
    
    # Initialize system
    sensory = OmegaSensorySystem()
    
    # Start all sensors
    results = sensory.start_all()
    
    print("\n" + "=" * 70)
    print("OMEGA SENSORY SYSTEM STATUS")
    print("=" * 70)
    
    status = sensory.get_status()
    for sensor_name, sensor_status in status.items():
        available = "✅" if sensor_status["available"] else "❌"
        active = "🟢" if sensor_status["active"] else "⚫"
        print(f"{available} {active} {sensor_name.upper()}")
    
    print("=" * 70)
    
    # Test CPU and Internet (always available)
    print("\n🔍 Testing CPU sensor...")
    cpu_metrics = sensory.cpu.get_metrics()
    print(f"  CPU: {cpu_metrics.get('cpu_percent', 0):.1f}%")
    print(f"  Memory: {cpu_metrics.get('memory_percent', 0):.1f}%")
    
    print("\n🔍 Testing Internet sensor...")
    net_stats = sensory.internet.get_network_stats()
    print(f"  Bytes Sent: {net_stats.get('bytes_sent', 0):,}")
    print(f"  Bytes Recv: {net_stats.get('bytes_recv', 0):,}")
    
    print("\n✅ Sensory system operational")
    
    # Stop all
    sensory.stop_all()
