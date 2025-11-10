#!/usr/bin/env python3
"""
PROMETHEUS PRIME - KILLSWITCH MONITOR
100ms response time emergency stop system

Authority Level: 11.0
Commander: Bobby Don McWilliams II
CRITICAL SAFETY SYSTEM - DO NOT MODIFY WITHOUT AUTHORIZATION
"""

import time
import threading
import redis
import logging
import sys
from datetime import datetime
from typing import Callable, List
import signal

class KillswitchMonitor:
    """
    Emergency killswitch with 100ms response time.
    Monitors Redis key and terminates all operations instantly on trigger.
    """

    def __init__(self,
                 redis_host: str = 'localhost',
                 redis_port: int = 6379,
                 check_interval: float = 0.1):  # 100ms
        """
        Initialize killswitch monitor.

        Args:
            redis_host: Redis server host
            redis_port: Redis server port
            check_interval: Check interval in seconds (default 100ms)
        """
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1
        )
        self.check_interval = check_interval
        self.running = False
        self.shutdown_callbacks: List[Callable] = []

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - KILLSWITCH - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/killswitch.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('KILLSWITCH')

        # Redis keys
        self.killswitch_key = 'prometheus:killswitch'
        self.heartbeat_key = 'prometheus:killswitch:heartbeat'
        self.status_key = 'prometheus:killswitch:status'

        # Initialize killswitch state
        self.redis_client.set(self.killswitch_key, 'ACTIVE')
        self.redis_client.set(self.status_key, 'MONITORING')

    def register_shutdown_callback(self, callback: Callable):
        """Register a callback to be executed on emergency shutdown."""
        self.shutdown_callbacks.append(callback)
        self.logger.info(f"Registered shutdown callback: {callback.__name__}")

    def start_monitoring(self):
        """Start the killswitch monitoring thread."""
        if self.running:
            self.logger.warning("Killswitch monitor already running")
            return

        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="KillswitchMonitor"
        )
        self.monitor_thread.start()
        self.logger.info(f"Killswitch monitoring started (interval: {self.check_interval*1000}ms)")

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle system signals for graceful shutdown."""
        self.logger.warning(f"Received signal {signum}, triggering killswitch")
        self.trigger_killswitch(reason="System signal received")

    def _monitoring_loop(self):
        """Main monitoring loop - checks every 100ms."""
        consecutive_failures = 0
        max_failures = 5

        while self.running:
            try:
                # Update heartbeat
                self.redis_client.set(
                    self.heartbeat_key,
                    datetime.utcnow().isoformat(),
                    ex=5  # Expire in 5 seconds
                )

                # Check killswitch state
                state = self.redis_client.get(self.killswitch_key)

                if state == 'STOP' or state == 'EMERGENCY_STOP':
                    self.logger.critical("⚠️  KILLSWITCH ACTIVATED ⚠️")
                    self._emergency_shutdown(reason=f"Killswitch state: {state}")
                    break

                consecutive_failures = 0

            except redis.ConnectionError as e:
                consecutive_failures += 1
                self.logger.error(f"Redis connection error ({consecutive_failures}/{max_failures}): {e}")

                if consecutive_failures >= max_failures:
                    self.logger.critical("Redis connection lost - triggering failsafe shutdown")
                    self._emergency_shutdown(reason="Redis connection lost")
                    break

            except Exception as e:
                self.logger.error(f"Unexpected error in monitoring loop: {e}")

            time.sleep(self.check_interval)

    def _emergency_shutdown(self, reason: str):
        """Execute emergency shutdown sequence."""
        self.logger.critical("=" * 80)
        self.logger.critical("🚨 EMERGENCY SHUTDOWN INITIATED 🚨")
        self.logger.critical(f"Reason: {reason}")
        self.logger.critical(f"Timestamp: {datetime.utcnow().isoformat()}")
        self.logger.critical("=" * 80)

        # Update status
        try:
            self.redis_client.set(self.status_key, 'EMERGENCY_SHUTDOWN')
            self.redis_client.set(
                'prometheus:shutdown:reason',
                reason,
                ex=86400  # Keep for 24 hours
            )
        except:
            pass

        # Execute all shutdown callbacks
        for callback in self.shutdown_callbacks:
            try:
                self.logger.info(f"Executing shutdown callback: {callback.__name__}")
                callback()
            except Exception as e:
                self.logger.error(f"Error in shutdown callback {callback.__name__}: {e}")

        # Final log
        self.logger.critical("🛑 ALL OPERATIONS TERMINATED 🛑")
        self.running = False

        # Force exit
        sys.exit(1)

    def trigger_killswitch(self, reason: str = "Manual trigger"):
        """Manually trigger the killswitch."""
        self.logger.warning(f"Killswitch manually triggered: {reason}")
        try:
            self.redis_client.set(self.killswitch_key, 'STOP')
        except Exception as e:
            self.logger.error(f"Failed to set killswitch: {e}")
            # Failsafe - trigger shutdown directly
            self._emergency_shutdown(reason=f"Manual trigger: {reason}")

    def get_status(self) -> dict:
        """Get current killswitch status."""
        try:
            return {
                'running': self.running,
                'state': self.redis_client.get(self.killswitch_key),
                'status': self.redis_client.get(self.status_key),
                'last_heartbeat': self.redis_client.get(self.heartbeat_key),
                'check_interval_ms': self.check_interval * 1000
            }
        except Exception as e:
            return {'error': str(e)}

    def reset_killswitch(self, authorization_code: str):
        """
        Reset killswitch after emergency stop.
        Requires authorization code.
        """
        # CRITICAL: Only authorized personnel can reset
        AUTHORIZED_CODE = "PROMETHEUS_PRIME_RESET_11.0"  # Change this!

        if authorization_code != AUTHORIZED_CODE:
            self.logger.error("Unauthorized killswitch reset attempt")
            return False

        self.logger.info("Killswitch reset authorized")
        self.redis_client.set(self.killswitch_key, 'ACTIVE')
        self.redis_client.set(self.status_key, 'MONITORING')
        return True


# ============================================================================
# HARDWARE KILLSWITCH INTEGRATION
# ============================================================================

class HardwareKillswitch:
    """
    Physical hardware killswitch integration.
    Monitors GPIO pin on Raspberry Pi or USB device.
    """

    def __init__(self, monitor: KillswitchMonitor, pin: int = 17):
        """
        Initialize hardware killswitch.

        Args:
            monitor: KillswitchMonitor instance to trigger
            pin: GPIO pin number (BCM numbering)
        """
        self.monitor = monitor
        self.pin = pin
        self.enabled = False

        try:
            import RPi.GPIO as GPIO
            self.GPIO = GPIO
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
            GPIO.add_event_detect(
                pin,
                GPIO.FALLING,
                callback=self._hardware_trigger,
                bouncetime=200
            )
            self.enabled = True
            monitor.logger.info(f"Hardware killswitch enabled on GPIO {pin}")
        except ImportError:
            monitor.logger.warning("RPi.GPIO not available - hardware killswitch disabled")
        except Exception as e:
            monitor.logger.error(f"Failed to setup hardware killswitch: {e}")

    def _hardware_trigger(self, channel):
        """Callback when hardware killswitch is activated."""
        self.monitor.logger.critical("🔴 HARDWARE KILLSWITCH ACTIVATED 🔴")
        self.monitor.trigger_killswitch(reason="Hardware button pressed")


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Initialize killswitch
    killswitch = KillswitchMonitor(check_interval=0.1)  # 100ms

    # Register shutdown callbacks
    def stop_omega_agents():
        print("Stopping all OMEGA agents...")
        # Integration with OMEGA_SWARM_BRAIN

    def close_all_sessions():
        print("Closing all active sessions...")
        # Close SSH, RDP, SMB sessions

    def lock_tools():
        print("Locking all tools...")
        # Disable tool execution

    killswitch.register_shutdown_callback(stop_omega_agents)
    killswitch.register_shutdown_callback(close_all_sessions)
    killswitch.register_shutdown_callback(lock_tools)

    # Optional: Enable hardware killswitch
    # hardware_killswitch = HardwareKillswitch(killswitch, pin=17)

    # Start monitoring
    killswitch.start_monitoring()

    print("Killswitch monitoring active. Press Ctrl+C to trigger.")
    print(f"Status: {killswitch.get_status()}")

    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nManual interrupt detected")
        killswitch.trigger_killswitch(reason="Keyboard interrupt")
