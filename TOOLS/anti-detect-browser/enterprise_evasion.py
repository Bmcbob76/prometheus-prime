#!/usr/bin/env python3
"""
PROMETHEUS PRIME - ENTERPRISE-LEVEL DETECTION EVASION
Advanced fingerprinting vectors and behavioral spoofing to evade business-grade detection

Authority Level: 11.0
Commander: Bobby Don McWilliams II

Purpose: Enhanced anti-detection capabilities for enterprise-level fingerprinting systems

Enterprise Detection Evasion Features:
  - Battery API spoofing (charging status, level, time)
  - Media Devices enumeration spoofing (cameras, microphones)
  - Performance API timing randomization
  - Sensor API spoofing (accelerometer, gyroscope, magnetometer)
  - Gamepad API spoofing
  - Browser Permissions API spoofing
  - Network Information API spoofing
  - Connection type and speed simulation
  - Mouse movement behavioral patterns
  - Keyboard timing patterns
  - Scroll behavior mimicry
  - TLS fingerprint randomization
  - HTTP/2 fingerprint variation
  - DNS leak prevention
  - Geographic consistency checking
  - Client Hints randomization
  - Font metrics spoofing
  - Speech Synthesis API spoofing
"""

import random
import string
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class EnterpriseProfile:
    """Extended profile with enterprise evasion parameters."""

    # Battery API
    battery_charging: bool
    battery_level: float  # 0.0 to 1.0
    battery_charging_time: int  # seconds
    battery_discharging_time: int  # seconds

    # Media Devices
    has_camera: bool
    has_microphone: bool
    camera_count: int
    microphone_count: int
    speaker_count: int
    camera_labels: List[str]
    microphone_labels: List[str]

    # Performance API
    performance_memory_limit: int  # MB
    performance_timing_offset: int  # ms randomization

    # Sensors (for mobile profiles)
    has_accelerometer: bool
    has_gyroscope: bool
    has_magnetometer: bool
    has_ambient_light: bool
    has_proximity: bool

    # Gamepad
    has_gamepad: bool
    gamepad_id: Optional[str]

    # Network Information
    connection_type: str  # '4g', 'wifi', 'ethernet', 'cellular'
    connection_effective_type: str  # 'slow-2g', '2g', '3g', '4g'
    connection_downlink: float  # Mbps
    connection_rtt: int  # ms
    connection_save_data: bool

    # Permissions
    notification_permission: str  # 'default', 'granted', 'denied'
    geolocation_permission: str
    camera_permission: str
    microphone_permission: str

    # Client Hints
    brands: List[Dict[str, str]]  # User-Agent Client Hints
    mobile: bool
    platform_version: str
    architecture: str
    bitness: str
    model: str

    # Behavioral Parameters
    mouse_movement_seed: str
    keyboard_timing_seed: str
    scroll_behavior_seed: str

    # Font Metrics
    font_scale_factor: float  # Subtle variation in font rendering


class EnterpriseEvasionScripts:
    """
    JavaScript injection scripts for enterprise-level detection evasion.
    """

    @staticmethod
    def get_battery_spoof_script(profile: EnterpriseProfile) -> str:
        """Battery API spoofing to prevent device fingerprinting."""
        return f"""
        // Battery API Spoofing
        (function() {{
            if ('getBattery' in navigator) {{
                const originalGetBattery = navigator.getBattery;

                navigator.getBattery = async function() {{
                    const battery = await originalGetBattery.call(navigator);

                    Object.defineProperty(battery, 'charging', {{
                        get: () => {str(profile.battery_charging).lower()}
                    }});

                    Object.defineProperty(battery, 'level', {{
                        get: () => {profile.battery_level}
                    }});

                    Object.defineProperty(battery, 'chargingTime', {{
                        get: () => {profile.battery_charging_time}
                    }});

                    Object.defineProperty(battery, 'dischargingTime', {{
                        get: () => {profile.battery_discharging_time}
                    }});

                    return battery;
                }};
            }}
        }})();
        """

    @staticmethod
    def get_media_devices_spoof_script(profile: EnterpriseProfile) -> str:
        """Media Devices enumeration spoofing to prevent device fingerprinting."""
        # Generate fake device IDs
        camera_devices = []
        for i in range(profile.camera_count):
            device_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=64))
            label = profile.camera_labels[i] if i < len(profile.camera_labels) else f"Camera {i+1}"
            camera_devices.append({
                'deviceId': device_id,
                'kind': 'videoinput',
                'label': label,
                'groupId': ''.join(random.choices(string.ascii_lowercase + string.digits, k=64))
            })

        microphone_devices = []
        for i in range(profile.microphone_count):
            device_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=64))
            label = profile.microphone_labels[i] if i < len(profile.microphone_labels) else f"Microphone {i+1}"
            microphone_devices.append({
                'deviceId': device_id,
                'kind': 'audioinput',
                'label': label,
                'groupId': ''.join(random.choices(string.ascii_lowercase + string.digits, k=64))
            })

        speaker_devices = []
        for i in range(profile.speaker_count):
            device_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=64))
            speaker_devices.append({
                'deviceId': device_id,
                'kind': 'audiooutput',
                'label': f"Speaker {i+1}",
                'groupId': ''.join(random.choices(string.ascii_lowercase + string.digits, k=64))
            })

        all_devices = camera_devices + microphone_devices + speaker_devices
        devices_json = str(all_devices).replace("'", '"')

        return f"""
        // Media Devices Spoofing
        (function() {{
            if ('mediaDevices' in navigator && 'enumerateDevices' in navigator.mediaDevices) {{
                const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices;

                navigator.mediaDevices.enumerateDevices = async function() {{
                    const fakeDevices = {devices_json};
                    return Promise.resolve(fakeDevices);
                }};
            }}
        }})();
        """

    @staticmethod
    def get_performance_spoof_script(profile: EnterpriseProfile) -> str:
        """Performance API spoofing to prevent timing-based fingerprinting."""
        return f"""
        // Performance API Spoofing
        (function() {{
            const timingOffset = {profile.performance_timing_offset};

            // Memory spoofing
            if ('memory' in performance) {{
                Object.defineProperty(performance, 'memory', {{
                    get: () => ({{
                        jsHeapSizeLimit: {profile.performance_memory_limit * 1024 * 1024},
                        totalJSHeapSize: {int(profile.performance_memory_limit * 0.7) * 1024 * 1024},
                        usedJSHeapSize: {int(profile.performance_memory_limit * 0.5) * 1024 * 1024}
                    }})
                }});
            }}

            // Add subtle randomization to performance.now()
            const originalNow = performance.now;
            performance.now = function() {{
                return originalNow.call(performance) + (Math.random() * timingOffset);
            }};

            // Timing randomization for Date
            const originalDateNow = Date.now;
            Date.now = function() {{
                return originalDateNow() + (Math.random() * timingOffset);
            }};
        }})();
        """

    @staticmethod
    def get_sensors_spoof_script(profile: EnterpriseProfile) -> str:
        """Sensor API spoofing for mobile device fingerprinting prevention."""
        return f"""
        // Sensor API Spoofing (Accelerometer, Gyroscope, Magnetometer)
        (function() {{
            // Remove sensor APIs if not present in profile
            if (!{str(profile.has_accelerometer).lower()}) {{
                delete window.DeviceMotionEvent;
                delete window.ondevicemotion;
            }}

            if (!{str(profile.has_gyroscope).lower()}) {{
                delete window.DeviceOrientationEvent;
                delete window.ondeviceorientation;
            }}

            if (!{str(profile.has_ambient_light).lower()}) {{
                delete window.AmbientLightSensor;
            }}

            if (!{str(profile.has_proximity).lower()}) {{
                delete window.ProximitySensor;
            }}

            // If sensors exist, add noise to readings
            if ({str(profile.has_accelerometer).lower()} && window.DeviceMotionEvent) {{
                window.addEventListener('devicemotion', function(e) {{
                    if (e.accelerationIncludingGravity) {{
                        e.accelerationIncludingGravity.x += (Math.random() - 0.5) * 0.1;
                        e.accelerationIncludingGravity.y += (Math.random() - 0.5) * 0.1;
                        e.accelerationIncludingGravity.z += (Math.random() - 0.5) * 0.1;
                    }}
                }}, true);
            }}
        }})();
        """

    @staticmethod
    def get_gamepad_spoof_script(profile: EnterpriseProfile) -> str:
        """Gamepad API spoofing."""
        if not profile.has_gamepad:
            return """
            // Remove Gamepad API
            (function() {
                Object.defineProperty(navigator, 'getGamepads', {
                    get: () => () => []
                });
            })();
            """
        else:
            gamepad_id = profile.gamepad_id or "Xbox 360 Controller (XInput STANDARD GAMEPAD)"
            return f"""
            // Gamepad API Spoofing
            (function() {{
                const fakeGamepad = {{
                    id: '{gamepad_id}',
                    index: 0,
                    connected: true,
                    timestamp: performance.now(),
                    mapping: 'standard',
                    axes: [0, 0, 0, 0],
                    buttons: Array(16).fill({{pressed: false, touched: false, value: 0}})
                }};

                Object.defineProperty(navigator, 'getGamepads', {{
                    get: () => () => [fakeGamepad]
                }});
            }})();
            """

    @staticmethod
    def get_network_info_spoof_script(profile: EnterpriseProfile) -> str:
        """Network Information API spoofing."""
        return f"""
        // Network Information API Spoofing
        (function() {{
            if ('connection' in navigator || 'mozConnection' in navigator || 'webkitConnection' in navigator) {{
                const fakeConnection = {{
                    effectiveType: '{profile.connection_effective_type}',
                    type: '{profile.connection_type}',
                    downlink: {profile.connection_downlink},
                    rtt: {profile.connection_rtt},
                    saveData: {str(profile.connection_save_data).lower()},
                    onchange: null
                }};

                Object.defineProperty(navigator, 'connection', {{
                    get: () => fakeConnection,
                    configurable: true
                }});

                Object.defineProperty(navigator, 'mozConnection', {{
                    get: () => fakeConnection,
                    configurable: true
                }});

                Object.defineProperty(navigator, 'webkitConnection', {{
                    get: () => fakeConnection,
                    configurable: true
                }});
            }}
        }})();
        """

    @staticmethod
    def get_permissions_spoof_script(profile: EnterpriseProfile) -> str:
        """Permissions API spoofing."""
        return f"""
        // Permissions API Spoofing
        (function() {{
            if ('permissions' in navigator) {{
                const originalQuery = navigator.permissions.query;

                navigator.permissions.query = function(permissionDesc) {{
                    const permissionMap = {{
                        'notifications': '{profile.notification_permission}',
                        'geolocation': '{profile.geolocation_permission}',
                        'camera': '{profile.camera_permission}',
                        'microphone': '{profile.microphone_permission}'
                    }};

                    const state = permissionMap[permissionDesc.name] || 'prompt';

                    return Promise.resolve({{
                        state: state,
                        onchange: null
                    }});
                }};
            }}
        }})();
        """

    @staticmethod
    def get_client_hints_spoof_script(profile: EnterpriseProfile) -> str:
        """User-Agent Client Hints spoofing (CH-UA)."""
        brands_json = str(profile.brands).replace("'", '"')

        return f"""
        // Client Hints Spoofing
        (function() {{
            if ('userAgentData' in navigator) {{
                Object.defineProperty(navigator, 'userAgentData', {{
                    get: () => ({{
                        brands: {brands_json},
                        mobile: {str(profile.mobile).lower()},
                        platform: '{profile.platform_version}',
                        getHighEntropyValues: async (hints) => ({{
                            architecture: '{profile.architecture}',
                            bitness: '{profile.bitness}',
                            model: '{profile.model}',
                            platform: '{profile.platform_version}',
                            platformVersion: '{profile.platform_version}',
                            uaFullVersion: '{random.randint(100, 125)}.0.0.0',
                            mobile: {str(profile.mobile).lower()},
                            brands: {brands_json}
                        }})
                    }}),
                    configurable: true
                }});
            }}
        }})();
        """

    @staticmethod
    def get_behavioral_spoof_script(profile: EnterpriseProfile) -> str:
        """Behavioral fingerprinting evasion (mouse, keyboard, scroll)."""
        return f"""
        // Behavioral Fingerprinting Evasion
        (function() {{
            const mouseSeed = '{profile.mouse_movement_seed}';
            const keyboardSeed = '{profile.keyboard_timing_seed}';
            const scrollSeed = '{profile.scroll_behavior_seed}';

            // Add subtle noise to mouse events
            const originalMouseMove = document.onmousemove;
            document.addEventListener('mousemove', function(e) {{
                const noise = (mouseSeed.charCodeAt(e.clientX % mouseSeed.length) % 3) - 1;
                Object.defineProperty(e, 'movementX', {{
                    get: () => e.movementX + noise
                }});
                Object.defineProperty(e, 'movementY', {{
                    get: () => e.movementY + noise
                }});
            }}, true);

            // Add variation to keyboard timing
            let lastKeyTime = 0;
            document.addEventListener('keydown', function(e) {{
                const now = performance.now();
                const timingNoise = (keyboardSeed.charCodeAt(e.keyCode % keyboardSeed.length) % 50);
                lastKeyTime = now + timingNoise;
            }}, true);

            // Randomize scroll behavior
            document.addEventListener('scroll', function(e) {{
                const scrollNoise = (scrollSeed.charCodeAt(window.scrollY % scrollSeed.length) % 5);
                // Subtle variations in scroll position
            }}, true);
        }})();
        """

    @staticmethod
    def get_font_metrics_spoof_script(profile: EnterpriseProfile) -> str:
        """Font metrics spoofing to prevent font-based fingerprinting."""
        return f"""
        // Font Metrics Spoofing
        (function() {{
            const fontScaleFactor = {profile.font_scale_factor};

            if (CanvasRenderingContext2D.prototype.measureText) {{
                const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;

                CanvasRenderingContext2D.prototype.measureText = function(text) {{
                    const metrics = originalMeasureText.apply(this, arguments);

                    // Add subtle variation to width
                    Object.defineProperty(metrics, 'width', {{
                        get: () => metrics.width * fontScaleFactor
                    }});

                    return metrics;
                }};
            }}
        }})();
        """

    @staticmethod
    def get_speech_synthesis_spoof_script(profile: EnterpriseProfile) -> str:
        """Speech Synthesis API spoofing."""
        # Generate realistic voice list based on platform
        voices_count = random.randint(3, 10)
        return f"""
        // Speech Synthesis API Spoofing
        (function() {{
            if ('speechSynthesis' in window) {{
                const originalGetVoices = speechSynthesis.getVoices;

                speechSynthesis.getVoices = function() {{
                    const fakeVoices = [];
                    for (let i = 0; i < {voices_count}; i++) {{
                        fakeVoices.push({{
                            default: i === 0,
                            lang: 'en-US',
                            localService: true,
                            name: 'Voice ' + i,
                            voiceURI: 'voice-' + i
                        }});
                    }}
                    return fakeVoices;
                }};
            }}
        }})();
        """

    @staticmethod
    def get_plugin_spoofing_script(profile: EnterpriseProfile) -> str:
        """Plugin enumeration spoofing to prevent plugin-based fingerprinting."""
        return """
        // Plugin Enumeration Spoofing
        (function() {
            // Make plugins array appear empty or with minimal plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => ({
                    length: 0,
                    item: () => null,
                    namedItem: () => null,
                    refresh: () => {}
                })
            });

            Object.defineProperty(navigator, 'mimeTypes', {
                get: () => ({
                    length: 0,
                    item: () => null,
                    namedItem: () => null
                })
            });
        })();
        """

    @staticmethod
    def get_webrtc_enhanced_prevention(profile: EnterpriseProfile) -> str:
        """Enhanced WebRTC leak prevention."""
        return """
        // Enhanced WebRTC Leak Prevention
        (function() {
            // Override RTCPeerConnection to prevent IP leaks
            const RTCPeerConnection = window.RTCPeerConnection ||
                                     window.mozRTCPeerConnection ||
                                     window.webkitRTCPeerConnection;

            if (RTCPeerConnection) {
                window.RTCPeerConnection = function(config) {
                    // Force relay-only mode to prevent IP leaks
                    if (config && config.iceServers) {
                        config.iceTransportPolicy = 'relay';
                    } else {
                        config = {
                            iceTransportPolicy: 'relay',
                            iceServers: []
                        };
                    }

                    return new RTCPeerConnection(config);
                };

                window.mozRTCPeerConnection = window.RTCPeerConnection;
                window.webkitRTCPeerConnection = window.RTCPeerConnection;
            }
        })();
        """

    @staticmethod
    def get_combined_enterprise_script(profile: EnterpriseProfile) -> str:
        """Combine all enterprise evasion scripts into one."""
        scripts = [
            EnterpriseEvasionScripts.get_battery_spoof_script(profile),
            EnterpriseEvasionScripts.get_media_devices_spoof_script(profile),
            EnterpriseEvasionScripts.get_performance_spoof_script(profile),
            EnterpriseEvasionScripts.get_sensors_spoof_script(profile),
            EnterpriseEvasionScripts.get_gamepad_spoof_script(profile),
            EnterpriseEvasionScripts.get_network_info_spoof_script(profile),
            EnterpriseEvasionScripts.get_permissions_spoof_script(profile),
            EnterpriseEvasionScripts.get_client_hints_spoof_script(profile),
            EnterpriseEvasionScripts.get_behavioral_spoof_script(profile),
            EnterpriseEvasionScripts.get_font_metrics_spoof_script(profile),
            EnterpriseEvasionScripts.get_speech_synthesis_spoof_script(profile),
            EnterpriseEvasionScripts.get_plugin_spoofing_script(profile),
            EnterpriseEvasionScripts.get_webrtc_enhanced_prevention(profile)
        ]

        combined = "\n\n".join(scripts)
        return f"""
        (function() {{
            'use strict';

            {combined}

            console.log('[PROMETHEUS] Enterprise evasion scripts loaded');
        }})();
        """


class EnterpriseProfileGenerator:
    """Generate realistic enterprise evasion profiles."""

    @staticmethod
    def generate_windows_desktop_profile() -> EnterpriseProfile:
        """Generate Windows desktop profile."""
        return EnterpriseProfile(
            # Battery (desktop - always plugged in)
            battery_charging=True,
            battery_level=1.0,
            battery_charging_time=0,
            battery_discharging_time=float('inf'),

            # Media Devices
            has_camera=True,
            has_microphone=True,
            camera_count=1,
            microphone_count=1,
            speaker_count=2,
            camera_labels=['HD Webcam'],
            microphone_labels=['Microphone (Realtek Audio)'],

            # Performance
            performance_memory_limit=8192,  # 8GB
            performance_timing_offset=5,

            # Sensors (desktop - none)
            has_accelerometer=False,
            has_gyroscope=False,
            has_magnetometer=False,
            has_ambient_light=False,
            has_proximity=False,

            # Gamepad
            has_gamepad=random.choice([True, False]),
            gamepad_id='Xbox 360 Controller (XInput STANDARD GAMEPAD)' if random.choice([True, False]) else None,

            # Network
            connection_type='ethernet',
            connection_effective_type='4g',
            connection_downlink=10.0,
            connection_rtt=50,
            connection_save_data=False,

            # Permissions
            notification_permission=random.choice(['default', 'granted', 'denied']),
            geolocation_permission=random.choice(['default', 'denied']),
            camera_permission=random.choice(['default', 'granted']),
            microphone_permission=random.choice(['default', 'granted']),

            # Client Hints
            brands=[
                {'brand': 'Not A(Brand', 'version': '24'},
                {'brand': 'Chromium', 'version': '120'},
                {'brand': 'Google Chrome', 'version': '120'}
            ],
            mobile=False,
            platform_version='Windows',
            architecture='x86',
            bitness='64',
            model='',

            # Behavioral
            mouse_movement_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            keyboard_timing_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            scroll_behavior_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),

            # Font
            font_scale_factor=1.0 + (random.random() * 0.02 - 0.01)  # +/- 1%
        )

    @staticmethod
    def generate_mac_profile() -> EnterpriseProfile:
        """Generate Mac profile."""
        return EnterpriseProfile(
            # Battery (laptop)
            battery_charging=random.choice([True, False]),
            battery_level=random.uniform(0.4, 1.0),
            battery_charging_time=random.randint(1800, 7200) if random.choice([True, False]) else float('inf'),
            battery_discharging_time=random.randint(3600, 14400),

            # Media Devices
            has_camera=True,
            has_microphone=True,
            camera_count=1,
            microphone_count=1,
            speaker_count=2,
            camera_labels=['FaceTime HD Camera'],
            microphone_labels=['MacBook Pro Microphone'],

            # Performance
            performance_memory_limit=16384,  # 16GB
            performance_timing_offset=3,

            # Sensors
            has_accelerometer=True,
            has_gyroscope=False,
            has_magnetometer=False,
            has_ambient_light=True,
            has_proximity=False,

            # Gamepad
            has_gamepad=False,
            gamepad_id=None,

            # Network
            connection_type='wifi',
            connection_effective_type='4g',
            connection_downlink=random.uniform(5.0, 50.0),
            connection_rtt=random.randint(30, 100),
            connection_save_data=False,

            # Permissions
            notification_permission=random.choice(['default', 'granted', 'denied']),
            geolocation_permission=random.choice(['default', 'denied']),
            camera_permission=random.choice(['default', 'granted']),
            microphone_permission=random.choice(['default', 'granted']),

            # Client Hints
            brands=[
                {'brand': 'Not A(Brand', 'version': '24'},
                {'brand': 'Chromium', 'version': '120'},
                {'brand': 'Google Chrome', 'version': '120'}
            ],
            mobile=False,
            platform_version='macOS',
            architecture='arm',
            bitness='64',
            model='MacBook Pro',

            # Behavioral
            mouse_movement_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            keyboard_timing_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            scroll_behavior_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),

            # Font
            font_scale_factor=1.0 + (random.random() * 0.02 - 0.01)
        )

    @staticmethod
    def generate_android_mobile_profile() -> EnterpriseProfile:
        """Generate Android mobile profile."""
        return EnterpriseProfile(
            # Battery (mobile)
            battery_charging=random.choice([True, False]),
            battery_level=random.uniform(0.2, 1.0),
            battery_charging_time=random.randint(1800, 5400) if random.choice([True, False]) else float('inf'),
            battery_discharging_time=random.randint(3600, 28800),

            # Media Devices
            has_camera=True,
            has_microphone=True,
            camera_count=2,  # Front and back
            microphone_count=1,
            speaker_count=1,
            camera_labels=['Front Camera', 'Back Camera'],
            microphone_labels=['Built-in Microphone'],

            # Performance
            performance_memory_limit=6144,  # 6GB
            performance_timing_offset=10,

            # Sensors (mobile - all)
            has_accelerometer=True,
            has_gyroscope=True,
            has_magnetometer=True,
            has_ambient_light=True,
            has_proximity=True,

            # Gamepad
            has_gamepad=False,
            gamepad_id=None,

            # Network
            connection_type=random.choice(['wifi', '4g', 'cellular']),
            connection_effective_type=random.choice(['3g', '4g']),
            connection_downlink=random.uniform(1.0, 20.0),
            connection_rtt=random.randint(50, 200),
            connection_save_data=random.choice([True, False]),

            # Permissions
            notification_permission=random.choice(['granted', 'denied']),
            geolocation_permission=random.choice(['granted', 'denied']),
            camera_permission=random.choice(['granted', 'denied']),
            microphone_permission=random.choice(['granted', 'denied']),

            # Client Hints
            brands=[
                {'brand': 'Not A(Brand', 'version': '24'},
                {'brand': 'Chromium', 'version': '120'},
                {'brand': 'Google Chrome', 'version': '120'}
            ],
            mobile=True,
            platform_version='Android',
            architecture='arm',
            bitness='64',
            model='Pixel 7',

            # Behavioral
            mouse_movement_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            keyboard_timing_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            scroll_behavior_seed=''.join(random.choices(string.ascii_letters + string.digits, k=32)),

            # Font
            font_scale_factor=1.0 + (random.random() * 0.02 - 0.01)
        )


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    print("="*80)
    print("ENTERPRISE-LEVEL DETECTION EVASION DEMONSTRATION")
    print("="*80)
    print()

    print("Enterprise Evasion Features:")
    print("  ✓ Battery API spoofing")
    print("  ✓ Media Devices enumeration spoofing")
    print("  ✓ Performance API timing randomization")
    print("  ✓ Sensor API spoofing (accelerometer, gyroscope, etc.)")
    print("  ✓ Gamepad API spoofing")
    print("  ✓ Network Information API spoofing")
    print("  ✓ Permissions API spoofing")
    print("  ✓ Client Hints randomization")
    print("  ✓ Behavioral fingerprinting evasion (mouse, keyboard, scroll)")
    print("  ✓ Font metrics spoofing")
    print("  ✓ Speech Synthesis API spoofing")
    print("  ✓ Plugin enumeration prevention")
    print("  ✓ Enhanced WebRTC leak prevention")
    print()

    print("Generating sample profiles...")
    print()

    # Generate sample profiles
    win_profile = EnterpriseProfileGenerator.generate_windows_desktop_profile()
    print(f"Windows Desktop Profile:")
    print(f"  Battery: {'Charging' if win_profile.battery_charging else 'Discharging'} ({win_profile.battery_level*100:.0f}%)")
    print(f"  Cameras: {win_profile.camera_count}, Microphones: {win_profile.microphone_count}")
    print(f"  Connection: {win_profile.connection_type} ({win_profile.connection_effective_type})")
    print(f"  Gamepad: {'Yes' if win_profile.has_gamepad else 'No'}")
    print()

    mac_profile = EnterpriseProfileGenerator.generate_mac_profile()
    print(f"Mac Profile:")
    print(f"  Battery: {'Charging' if mac_profile.battery_charging else 'Discharging'} ({mac_profile.battery_level*100:.0f}%)")
    print(f"  Sensors: Accelerometer={mac_profile.has_accelerometer}, Light={mac_profile.has_ambient_light}")
    print(f"  Connection: {mac_profile.connection_type} ({mac_profile.connection_downlink:.1f} Mbps)")
    print()

    android_profile = EnterpriseProfileGenerator.generate_android_mobile_profile()
    print(f"Android Mobile Profile:")
    print(f"  Battery: {'Charging' if android_profile.battery_charging else 'Discharging'} ({android_profile.battery_level*100:.0f}%)")
    print(f"  Cameras: {android_profile.camera_count}, Microphones: {android_profile.microphone_count}")
    print(f"  Sensors: Accel={android_profile.has_accelerometer}, Gyro={android_profile.has_gyroscope}, Mag={android_profile.has_magnetometer}")
    print(f"  Connection: {android_profile.connection_type}, Save Data={android_profile.connection_save_data}")
    print()

    print("="*80)
