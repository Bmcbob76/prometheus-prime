"""
PROMETHEUS PRIME - COMPREHENSIVE LOGGING AND MONITORING
Advanced logging, metrics, and system monitoring

Capabilities:
- Multi-level logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Structured logging with JSON format
- Log rotation and archival
- Real-time metrics collection
- Performance monitoring
- Security event logging
- Audit trail generation
- Alert system
"""

import logging
import logging.handlers
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import threading


class PrometheusLogger:
    """
    Comprehensive logging and monitoring system

    Features:
    - Multi-destination logging (console, file, JSON)
    - Automatic log rotation
    - Real-time metrics
    - Security event tracking
    """

    def __init__(self, log_dir: str = "logs", log_level: str = "INFO"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

        self.log_level = getattr(logging, log_level.upper())

        # Initialize loggers
        self.logger = self._setup_main_logger()
        self.security_logger = self._setup_security_logger()
        self.audit_logger = self._setup_audit_logger()

        # Metrics
        self.metrics = {
            "operations_total": 0,
            "operations_successful": 0,
            "operations_failed": 0,
            "threats_detected": 0,
            "threats_blocked": 0,
            "start_time": time.time(),
            "domains_executed": {},
            "errors": []
        }

        self.metrics_lock = threading.Lock()

        self.logger.info("🚀 PROMETHEUS LOGGER INITIALIZED")

    def _setup_main_logger(self) -> logging.Logger:
        """Setup main application logger"""
        logger = logging.getLogger("PrometheusMain")
        logger.setLevel(self.log_level)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)

        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "prometheus.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=10
        )
        file_handler.setLevel(self.log_level)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)

        # JSON handler for structured logging
        json_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "prometheus.json",
            maxBytes=10*1024*1024,
            backupCount=5
        )
        json_handler.setLevel(logging.INFO)
        json_handler.setFormatter(JSONFormatter())

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        logger.addHandler(json_handler)

        return logger

    def _setup_security_logger(self) -> logging.Logger:
        """Setup security events logger"""
        logger = logging.getLogger("PrometheusSecur ity")
        logger.setLevel(logging.INFO)

        # Security log file
        security_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "security.log",
            maxBytes=50*1024*1024,  # 50MB
            backupCount=20
        )
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        security_handler.setFormatter(security_formatter)

        # JSON security log
        security_json = logging.handlers.RotatingFileHandler(
            self.log_dir / "security.json",
            maxBytes=50*1024*1024,
            backupCount=10
        )
        security_json.setFormatter(JSONFormatter())

        logger.addHandler(security_handler)
        logger.addHandler(security_json)

        return logger

    def _setup_audit_logger(self) -> logging.Logger:
        """Setup audit trail logger"""
        logger = logging.getLogger("PrometheusAudit")
        logger.setLevel(logging.INFO)

        # Audit log file (never rotated - permanent record)
        audit_handler = logging.FileHandler(
            self.log_dir / f"audit_{datetime.now().strftime('%Y%m')}.log",
            mode='a'
        )
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S.%f'
        )
        audit_handler.setFormatter(audit_formatter)

        logger.addHandler(audit_handler)

        return logger

    def log(self, level: str, message: str, **kwargs):
        """
        Log a message with additional context

        Args:
            level: Log level (debug, info, warning, error, critical)
            message: Log message
            **kwargs: Additional context
        """
        log_func = getattr(self.logger, level.lower())
        if kwargs:
            log_func(f"{message} | Context: {json.dumps(kwargs)}")
        else:
            log_func(message)

    def log_operation(self, operation: str, domain: str, status: str,
                     duration: float, details: Optional[Dict] = None):
        """Log an operation execution"""
        with self.metrics_lock:
            self.metrics["operations_total"] += 1

            if status == "success":
                self.metrics["operations_successful"] += 1
            else:
                self.metrics["operations_failed"] += 1

            # Track domain statistics
            if domain not in self.metrics["domains_executed"]:
                self.metrics["domains_executed"][domain] = {
                    "total": 0,
                    "successful": 0,
                    "failed": 0
                }

            self.metrics["domains_executed"][domain]["total"] += 1
            if status == "success":
                self.metrics["domains_executed"][domain]["successful"] += 1
            else:
                self.metrics["domains_executed"][domain]["failed"] += 1

        log_data = {
            "operation": operation,
            "domain": domain,
            "status": status,
            "duration_ms": duration * 1000,
            "timestamp": datetime.now().isoformat()
        }

        if details:
            log_data.update(details)

        level = "info" if status == "success" else "warning"
        self.log(level, f"Operation: {operation} [{domain}] - {status}", **log_data)

    def log_security_event(self, event_type: str, severity: str,
                          description: str, details: Optional[Dict] = None):
        """Log a security event"""
        with self.metrics_lock:
            if severity in ["HIGH", "CRITICAL"]:
                self.metrics["threats_detected"] += 1

        event_data = {
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "timestamp": datetime.now().isoformat()
        }

        if details:
            event_data.update(details)

        log_level = {
            "LOW": logging.INFO,
            "MEDIUM": logging.WARNING,
            "HIGH": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }.get(severity, logging.INFO)

        self.security_logger.log(
            log_level,
            f"[{severity}] {event_type}: {description} | {json.dumps(details or {})}"
        )

    def log_audit(self, action: str, user: str, resource: str,
                  result: str, details: Optional[Dict] = None):
        """Log an audit trail entry"""
        audit_data = {
            "action": action,
            "user": user,
            "resource": resource,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }

        if details:
            audit_data.update(details)

        self.audit_logger.info(json.dumps(audit_data))

    def log_error(self, error: Exception, context: Optional[Dict] = None):
        """Log an error with traceback"""
        import traceback

        error_data = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "traceback": traceback.format_exc(),
            "timestamp": datetime.now().isoformat()
        }

        if context:
            error_data.update(context)

        with self.metrics_lock:
            self.metrics["errors"].append({
                "type": type(error).__name__,
                "message": str(error),
                "timestamp": datetime.now().isoformat()
            })

            # Keep only last 100 errors
            if len(self.metrics["errors"]) > 100:
                self.metrics["errors"] = self.metrics["errors"][-100:]

        self.logger.error(f"Error occurred: {error}", exc_info=True)

    def get_metrics(self) -> Dict:
        """Get current metrics"""
        with self.metrics_lock:
            uptime = time.time() - self.metrics["start_time"]

            return {
                **self.metrics,
                "uptime_seconds": uptime,
                "uptime_formatted": self._format_uptime(uptime),
                "success_rate": (
                    self.metrics["operations_successful"] / self.metrics["operations_total"] * 100
                    if self.metrics["operations_total"] > 0 else 0
                ),
                "snapshot_time": datetime.now().isoformat()
            }

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime as human-readable string"""
        hours, remainder = divmod(int(seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}h {minutes}m {seconds}s"

    def export_metrics(self, filepath: str):
        """Export metrics to JSON file"""
        metrics = self.get_metrics()

        with open(filepath, 'w') as f:
            json.dump(metrics, f, indent=2)

        self.logger.info(f"📊 Metrics exported to {filepath}")

    def create_report(self) -> str:
        """Generate text report of system status"""
        metrics = self.get_metrics()

        report = f"""
╔══════════════════════════════════════════════════════════════╗
║           PROMETHEUS PRIME - SYSTEM STATUS REPORT            ║
╠══════════════════════════════════════════════════════════════╣
║ Uptime: {metrics['uptime_formatted']:<51} ║
║ Total Operations: {metrics['operations_total']:<44} ║
║ Successful: {metrics['operations_successful']:<50} ║
║ Failed: {metrics['operations_failed']:<54} ║
║ Success Rate: {metrics['success_rate']:.1f}%{' '*44} ║
║                                                              ║
║ Security:                                                    ║
║ Threats Detected: {metrics['threats_detected']:<46} ║
║ Threats Blocked: {metrics['threats_blocked']:<47} ║
║                                                              ║
║ Domain Execution Summary:                                    ║
"""

        for domain, stats in metrics['domains_executed'].items():
            report += f"║ {domain[:30]:<30}: {stats['total']:>3} ops ({stats['successful']} ok, {stats['failed']} fail){' '*(20-len(str(stats['total'])))} ║\n"

        report += f"""║                                                              ║
║ Recent Errors: {len(metrics['errors']):<45} ║
╚══════════════════════════════════════════════════════════════╝
"""

        return report


class JSONFormatter(logging.Formatter):
    """Format logs as JSON"""

    def format(self, record):
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class PerformanceMonitor:
    """Monitor system performance"""

    def __init__(self, logger: PrometheusLogger):
        self.logger = logger
        self.timers = {}
        self.lock = threading.Lock()

    def start_timer(self, operation: str):
        """Start timing an operation"""
        with self.lock:
            self.timers[operation] = time.time()

    def end_timer(self, operation: str, log_slow: bool = True,
                  slow_threshold: float = 1.0):
        """End timing and log if slow"""
        with self.lock:
            if operation not in self.timers:
                return 0.0

            duration = time.time() - self.timers[operation]
            del self.timers[operation]

        if log_slow and duration > slow_threshold:
            self.logger.log("warning", f"Slow operation detected: {operation}",
                          duration_seconds=duration,
                          threshold=slow_threshold)

        return duration

    def measure(self, operation: str):
        """Context manager for timing operations"""
        return TimerContext(self, operation)


class TimerContext:
    """Context manager for timing"""

    def __init__(self, monitor: PerformanceMonitor, operation: str):
        self.monitor = monitor
        self.operation = operation

    def __enter__(self):
        self.monitor.start_timer(self.operation)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.duration = self.monitor.end_timer(self.operation)
        return False


if __name__ == "__main__":
    # Test logging system
    print("📝 PROMETHEUS LOGGER TEST")
    print("="*60)

    logger = PrometheusLogger(log_dir="test_logs", log_level="DEBUG")

    # Test various log levels
    print("\n✅ Testing log levels...")
    logger.log("info", "System initialized")
    logger.log("warning", "Low memory detected", memory_mb=512)
    logger.log("error", "Connection failed", host="192.168.1.100", port=4444)

    # Test operation logging
    print("\n✅ Testing operation logging...")
    logger.log_operation("port_scan", "network_recon", "success", 2.5,
                        {"target": "192.168.1.0/24", "ports_found": 15})

    logger.log_operation("exploit_exec", "web_exploitation", "failed", 0.8,
                        {"target": "example.com", "error": "Connection timeout"})

    # Test security logging
    print("\n✅ Testing security logging...")
    logger.log_security_event("intrusion_attempt", "HIGH",
                             "Multiple failed login attempts",
                             {"source_ip": "10.0.0.50", "attempts": 10})

    # Test audit logging
    print("\n✅ Testing audit logging...")
    logger.log_audit("exploit_executed", "admin", "target_system",
                    "success", {"exploit": "CVE-2021-1234"})

    # Test error logging
    print("\n✅ Testing error logging...")
    try:
        raise ValueError("Test error for logging")
    except Exception as e:
        logger.log_error(e, {"operation": "test", "phase": "initialization"})

    # Test performance monitoring
    print("\n✅ Testing performance monitoring...")
    perf = PerformanceMonitor(logger)

    with perf.measure("test_operation"):
        time.sleep(0.1)

    # Get metrics
    print("\n📊 System Metrics:")
    metrics = logger.get_metrics()
    print(f"   Total operations: {metrics['operations_total']}")
    print(f"   Success rate: {metrics['success_rate']:.1f}%")

    # Generate report
    print("\n📋 System Report:")
    print(logger.create_report())

    print("\n✅ Logging system test complete")
    print(f"   Check logs in: test_logs/")
