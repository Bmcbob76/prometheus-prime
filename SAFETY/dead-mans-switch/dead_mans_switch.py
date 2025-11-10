#!/usr/bin/env python3
"""
PROMETHEUS PRIME - DEAD MAN'S SWITCH
Requires periodic check-ins or automatically triggers emergency shutdown

Authority Level: 11.0
Commander: Bobby Don McWilliams II
CRITICAL SAFETY SYSTEM - PREVENTS RUNAWAY AUTONOMOUS OPERATIONS
"""

import time
import threading
import logging
import sys
from datetime import datetime, timedelta
from typing import Callable, List, Optional
import redis


class DeadMansSwitch:
    """
    Dead man's switch requiring periodic check-ins.
    If operator doesn't check in within timeout, triggers emergency shutdown.
    """

    def __init__(self,
                 timeout_seconds: int = 3600,  # Default: 1 hour
                 redis_host: str = 'localhost',
                 redis_port: int = 6379,
                 check_interval: int = 60):    # Check every minute
        """
        Initialize dead man's switch.

        Args:
            timeout_seconds: Time in seconds before triggering shutdown
            redis_host: Redis server host
            redis_port: Redis server port
            check_interval: How often to check (in seconds)
        """
        self.timeout_seconds = timeout_seconds
        self.check_interval = check_interval

        # Redis client for distributed check-ins
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1
        )

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - DEADMAN - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/prometheus/deadman.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('DEADMAN')

        # State
        self.running = False
        self.last_checkin: Optional[datetime] = None
        self.shutdown_callbacks: List[Callable] = []

        # Redis keys
        self.checkin_key = 'prometheus:deadman:last_checkin'
        self.timeout_key = 'prometheus:deadman:timeout'
        self.status_key = 'prometheus:deadman:status'

        # Initialize state in Redis
        self._initialize_redis()

        # Perform initial check-in
        self.checkin("Dead man's switch initialized")

    def _initialize_redis(self):
        """Initialize Redis state."""
        try:
            self.redis_client.set(self.timeout_key, self.timeout_seconds)
            self.redis_client.set(self.status_key, 'ACTIVE')
            self.logger.info("Dead man's switch Redis state initialized")
        except redis.ConnectionError as e:
            self.logger.error(f"Failed to initialize Redis: {e}")
            raise

    def register_shutdown_callback(self, callback: Callable):
        """Register a callback to be executed on timeout."""
        self.shutdown_callbacks.append(callback)
        self.logger.info(f"Registered shutdown callback: {callback.__name__}")

    def checkin(self, message: str = "Operator check-in"):
        """
        Perform a check-in to reset the timer.

        Args:
            message: Optional check-in message
        """
        now = datetime.utcnow()
        self.last_checkin = now

        try:
            # Store check-in time in Redis
            checkin_data = {
                'timestamp': now.isoformat(),
                'message': message
            }

            self.redis_client.set(
                self.checkin_key,
                now.isoformat(),
                ex=self.timeout_seconds * 2  # Keep for 2x timeout
            )

            self.logger.info(f"✓ Check-in received: {message} at {now.isoformat()}")
            return True

        except redis.ConnectionError as e:
            self.logger.error(f"Failed to record check-in: {e}")
            return False

    def start_monitoring(self):
        """Start the dead man's switch monitoring thread."""
        if self.running:
            self.logger.warning("Dead man's switch already running")
            return

        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="DeadMansSwitchMonitor"
        )
        self.monitor_thread.start()
        self.logger.info(f"Dead man's switch started (timeout: {self.timeout_seconds}s)")

    def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Get last check-in time from Redis
                last_checkin_str = self.redis_client.get(self.checkin_key)

                if not last_checkin_str:
                    self.logger.warning("No check-in found - triggering shutdown")
                    self._trigger_timeout()
                    break

                last_checkin = datetime.fromisoformat(last_checkin_str)
                time_since_checkin = (datetime.utcnow() - last_checkin).total_seconds()

                # Check if timeout exceeded
                if time_since_checkin > self.timeout_seconds:
                    self.logger.critical(
                        f"⏰ TIMEOUT EXCEEDED: {time_since_checkin:.0f}s since last check-in "
                        f"(timeout: {self.timeout_seconds}s)"
                    )
                    self._trigger_timeout()
                    break

                # Log time remaining
                time_remaining = self.timeout_seconds - time_since_checkin
                if time_remaining < 300:  # Less than 5 minutes
                    self.logger.warning(
                        f"⚠️  WARNING: Only {time_remaining:.0f}s until timeout"
                    )
                else:
                    self.logger.debug(
                        f"Time remaining: {time_remaining:.0f}s"
                    )

            except redis.ConnectionError as e:
                self.logger.error(f"Redis connection error: {e}")
                # Continue trying - don't trigger shutdown on connection errors

            except Exception as e:
                self.logger.error(f"Unexpected error in monitoring loop: {e}")

            time.sleep(self.check_interval)

    def _trigger_timeout(self):
        """Trigger emergency shutdown due to timeout."""
        self.logger.critical("=" * 80)
        self.logger.critical("🚨 DEAD MAN'S SWITCH TRIGGERED 🚨")
        self.logger.critical("No operator check-in received within timeout period")
        self.logger.critical(f"Last check-in: {self.last_checkin.isoformat() if self.last_checkin else 'NEVER'}")
        self.logger.critical(f"Timeout: {self.timeout_seconds} seconds")
        self.logger.critical(f"Timestamp: {datetime.utcnow().isoformat()}")
        self.logger.critical("=" * 80)

        # Update status in Redis
        try:
            self.redis_client.set(self.status_key, 'TIMEOUT_TRIGGERED')
            self.redis_client.set(
                'prometheus:deadman:trigger_reason',
                f"No check-in for {self.timeout_seconds} seconds",
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
        self.logger.critical("🛑 AUTONOMOUS OPERATIONS TERMINATED - OPERATOR INTERVENTION REQUIRED 🛑")
        self.running = False

        # Force exit
        sys.exit(1)

    def extend_timeout(self, additional_seconds: int, reason: str):
        """
        Extend the timeout period.

        Args:
            additional_seconds: Additional seconds to add to timeout
            reason: Reason for extension
        """
        old_timeout = self.timeout_seconds
        self.timeout_seconds += additional_seconds

        try:
            self.redis_client.set(self.timeout_key, self.timeout_seconds)
        except:
            pass

        self.logger.warning(
            f"Timeout extended: {old_timeout}s -> {self.timeout_seconds}s "
            f"(+{additional_seconds}s) - Reason: {reason}"
        )

        # Perform automatic check-in when extending
        self.checkin(f"Timeout extended: {reason}")

    def get_status(self) -> dict:
        """Get current dead man's switch status."""
        try:
            last_checkin_str = self.redis_client.get(self.checkin_key)
            timeout = self.redis_client.get(self.timeout_key)
            status = self.redis_client.get(self.status_key)

            if last_checkin_str:
                last_checkin = datetime.fromisoformat(last_checkin_str)
                time_since_checkin = (datetime.utcnow() - last_checkin).total_seconds()
                time_remaining = self.timeout_seconds - time_since_checkin
            else:
                last_checkin = None
                time_since_checkin = None
                time_remaining = None

            return {
                'running': self.running,
                'status': status,
                'timeout_seconds': self.timeout_seconds,
                'last_checkin': last_checkin_str,
                'time_since_checkin_seconds': time_since_checkin,
                'time_remaining_seconds': time_remaining,
                'check_interval_seconds': self.check_interval
            }
        except Exception as e:
            return {'error': str(e)}

    def disable(self, authorization_code: str):
        """
        Disable the dead man's switch (requires authorization).

        Args:
            authorization_code: Authorization code

        Raises:
            ValueError: If authorization fails
        """
        # CRITICAL: Disabling should require strong authorization
        AUTHORIZED_CODE = "PROMETHEUS_DEADMAN_DISABLE_11.0"  # Change this!

        if authorization_code != AUTHORIZED_CODE:
            self.logger.error("Unauthorized dead man's switch disable attempt")
            raise ValueError("Invalid authorization code")

        self.running = False
        try:
            self.redis_client.set(self.status_key, 'DISABLED')
        except:
            pass

        self.logger.warning("⚠️  DEAD MAN'S SWITCH DISABLED - AUTONOMOUS OPERATIONS UNMONITORED ⚠️")

    def reset(self, authorization_code: str):
        """
        Reset the dead man's switch after timeout.

        Args:
            authorization_code: Authorization code
        """
        AUTHORIZED_CODE = "PROMETHEUS_DEADMAN_RESET_11.0"  # Change this!

        if authorization_code != AUTHORIZED_CODE:
            self.logger.error("Unauthorized dead man's switch reset attempt")
            raise ValueError("Invalid authorization code")

        self.logger.info("Dead man's switch reset authorized")
        self._initialize_redis()
        self.checkin("Dead man's switch reset")
        self.running = True


# ============================================================================
# INTEGRATION WITH KILLSWITCH
# ============================================================================

class IntegratedSafetySystems:
    """
    Integrated safety system combining:
    - Killswitch (manual emergency stop)
    - Dead man's switch (timeout-based stop)
    - Both trigger the same shutdown callbacks
    """

    def __init__(self,
                 killswitch_check_interval: float = 0.1,  # 100ms
                 deadman_timeout: int = 3600,             # 1 hour
                 redis_host: str = 'localhost',
                 redis_port: int = 6379):
        """
        Initialize integrated safety systems.

        Args:
            killswitch_check_interval: Killswitch check interval (seconds)
            deadman_timeout: Dead man's switch timeout (seconds)
            redis_host: Redis server host
            redis_port: Redis server port
        """
        # Import killswitch
        import sys
        sys.path.append('/home/user/prometheus-prime/SAFETY/killswitch')
        from killswitch_monitor import KillswitchMonitor

        self.killswitch = KillswitchMonitor(
            redis_host=redis_host,
            redis_port=redis_port,
            check_interval=killswitch_check_interval
        )

        self.deadman = DeadMansSwitch(
            timeout_seconds=deadman_timeout,
            redis_host=redis_host,
            redis_port=redis_port
        )

        self.logger = logging.getLogger('INTEGRATED_SAFETY')

    def register_shutdown_callback(self, callback: Callable):
        """Register shutdown callback for both systems."""
        self.killswitch.register_shutdown_callback(callback)
        self.deadman.register_shutdown_callback(callback)
        self.logger.info(f"Registered shutdown callback for both systems: {callback.__name__}")

    def start_all(self):
        """Start both safety systems."""
        self.killswitch.start_monitoring()
        self.deadman.start_monitoring()
        self.logger.info("All safety systems started")

    def checkin(self, message: str = "Operator check-in"):
        """Perform check-in to reset dead man's switch."""
        return self.deadman.checkin(message)

    def get_status(self) -> dict:
        """Get status of all safety systems."""
        return {
            'killswitch': self.killswitch.get_status(),
            'deadman': self.deadman.get_status()
        }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Initialize dead man's switch with 5 minute timeout for testing
    deadman = DeadMansSwitch(
        timeout_seconds=300,  # 5 minutes
        check_interval=30     # Check every 30 seconds
    )

    # Register shutdown callbacks
    def stop_all_agents():
        print("Stopping all OMEGA agents...")

    def close_all_connections():
        print("Closing all connections...")

    def save_state():
        print("Saving state before shutdown...")

    deadman.register_shutdown_callback(stop_all_agents)
    deadman.register_shutdown_callback(close_all_connections)
    deadman.register_shutdown_callback(save_state)

    # Start monitoring
    deadman.start_monitoring()

    print("Dead man's switch active. Performing periodic check-ins...")
    print(f"Timeout: {deadman.timeout_seconds} seconds")
    print(f"Status: {deadman.get_status()}")

    # Simulate periodic check-ins
    try:
        for i in range(5):
            time.sleep(60)  # Wait 1 minute
            deadman.checkin(f"Operator check-in #{i+1}")
            status = deadman.get_status()
            print(f"\nCheck-in #{i+1}")
            print(f"Time remaining: {status['time_remaining_seconds']:.0f}s")

        # Simulate forgetting to check in
        print("\n⚠️  Operator has stopped checking in...")
        print("Dead man's switch will trigger in 5 minutes...")

        # Keep running until timeout
        while deadman.running:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nManual interrupt - triggering shutdown...")
        deadman._trigger_timeout()
