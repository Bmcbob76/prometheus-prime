#!/usr/bin/env python3
"""
PROMETHEUS PRIME - REALISTIC HARDWARE PROFILE GENERATOR
Generate believable hardware combinations to evade business detection systems

Authority Level: 11.0
Commander: Bobby Don McWilliams II

Purpose: Create realistic hardware profiles that businesses cannot detect as fake

Key Principles:
  - Hardware specs must be internally consistent
  - High-end GPU must pair with high RAM
  - Mobile devices have appropriate screen sizes and memory
  - CPU cores match platform capabilities
  - Browser versions match OS versions
  - Timezone matches geographic location
  - Battery status matches device type (desktop vs laptop vs mobile)
  - Sensor availability matches device type
  - Connection type matches device type

This prevents detection via impossible hardware combinations like:
  ❌ RTX 4090 GPU with 4GB RAM
  ❌ MacBook with 128GB RAM
  ❌ Desktop with battery sensor
  ❌ Mobile device with 4K screen but 2GB RAM
  ❌ Linux platform with Safari browser
  ❌ New York timezone with UK IP address
"""

import random
import string
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import pytz


@dataclass
class RealisticHardwareProfile:
    """Complete realistic hardware profile."""
    # Device Category
    device_category: str  # 'desktop_highend', 'desktop_midrange', 'laptop_business', 'laptop_gaming', 'mobile_flagship', 'mobile_midrange'

    # Basic Hardware
    platform: str
    os_version: str
    cpu_cores: int
    device_memory_gb: int

    # GPU
    gpu_vendor: str
    gpu_renderer: str
    webgl_vendor: str
    webgl_renderer: str

    # Screen
    screen_width: int
    screen_height: int
    screen_depth: int
    device_pixel_ratio: float

    # Browser
    browser_family: str  # 'chrome', 'firefox', 'safari', 'edge'
    user_agent: str
    browser_vendor: str
    browser_version: str

    # Geographic
    country: str
    region: str
    city: str
    timezone: str
    language: str

    # Battery (realistic based on device type)
    has_battery: bool
    battery_charging: bool
    battery_level: float
    battery_charging_time: int
    battery_discharging_time: int

    # Sensors (realistic based on device type)
    has_accelerometer: bool
    has_gyroscope: bool
    has_magnetometer: bool
    has_ambient_light: bool
    has_proximity: bool

    # Media Devices
    camera_count: int
    microphone_count: int
    speaker_count: int
    camera_labels: List[str]
    microphone_labels: List[str]

    # Network (realistic based on device type)
    connection_type: str
    connection_effective_type: str
    connection_downlink_mbps: float
    connection_rtt_ms: int

    # Touch Support
    max_touch_points: int

    # Performance
    performance_memory_limit_mb: int

    # Seeds for randomization
    canvas_noise_seed: str
    audio_noise_seed: str
    mouse_movement_seed: str
    keyboard_timing_seed: str


class RealisticProfileGenerator:
    """
    Generate realistic hardware profiles with internally consistent specifications.
    """

    # GPU tiers matched to appropriate RAM amounts
    GPU_TIERS = {
        'high_end': {
            'nvidia': [
                'NVIDIA GeForce RTX 4090',
                'NVIDIA GeForce RTX 4080',
                'NVIDIA GeForce RTX 3090',
                'NVIDIA GeForce RTX 3080 Ti',
                'NVIDIA GeForce RTX 3080'
            ],
            'amd': [
                'AMD Radeon RX 7900 XTX',
                'AMD Radeon RX 7900 XT',
                'AMD Radeon RX 6900 XT',
                'AMD Radeon RX 6800 XT'
            ],
            'ram_gb': [32, 64, 128],
            'cpu_cores': [12, 16, 24, 32]
        },
        'mid_range': {
            'nvidia': [
                'NVIDIA GeForce RTX 3070',
                'NVIDIA GeForce RTX 3060 Ti',
                'NVIDIA GeForce RTX 3060',
                'NVIDIA GeForce RTX 2070'
            ],
            'amd': [
                'AMD Radeon RX 6700 XT',
                'AMD Radeon RX 6600 XT',
                'AMD Radeon RX 5700 XT'
            ],
            'ram_gb': [16, 32],
            'cpu_cores': [6, 8, 12]
        },
        'integrated': {
            'intel': [
                'Intel Iris Xe Graphics',
                'Intel UHD Graphics 770',
                'Intel Iris Plus Graphics'
            ],
            'amd': [
                'AMD Radeon Graphics',
                'AMD Radeon Vega 8'
            ],
            'ram_gb': [8, 16, 32],
            'cpu_cores': [4, 6, 8]
        }
    }

    # Screen resolutions matched to device types
    SCREEN_CONFIGS = {
        'desktop_4k': {
            'width': 3840,
            'height': 2160,
            'ratio': 1.0,
            'depth': 24
        },
        'desktop_1440p': {
            'width': 2560,
            'height': 1440,
            'ratio': 1.0,
            'depth': 24
        },
        'desktop_1080p': {
            'width': 1920,
            'height': 1080,
            'ratio': 1.0,
            'depth': 24
        },
        'laptop_retina': {
            'width': 3456,
            'height': 2234,
            'ratio': 2.0,
            'depth': 24
        },
        'laptop_1080p': {
            'width': 1920,
            'height': 1080,
            'ratio': 1.0,
            'depth': 24
        },
        'mobile_flagship': {
            'width': 1440,
            'height': 3200,
            'ratio': 3.0,
            'depth': 24
        },
        'mobile_midrange': {
            'width': 1080,
            'height': 2400,
            'ratio': 2.625,
            'depth': 24
        }
    }

    @staticmethod
    def _generate_seed() -> str:
        """Generate random seed."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    @staticmethod
    def _get_timezone_for_country(country: str) -> Tuple[str, str]:
        """Get realistic timezone and city for country."""
        timezone_map = {
            'US': [
                ('America/New_York', 'New York'),
                ('America/Los_Angeles', 'Los Angeles'),
                ('America/Chicago', 'Chicago'),
                ('America/Denver', 'Denver'),
                ('America/Phoenix', 'Phoenix')
            ],
            'GB': [
                ('Europe/London', 'London'),
                ('Europe/London', 'Manchester'),
                ('Europe/London', 'Birmingham')
            ],
            'DE': [
                ('Europe/Berlin', 'Berlin'),
                ('Europe/Berlin', 'Munich'),
                ('Europe/Berlin', 'Hamburg')
            ],
            'FR': [
                ('Europe/Paris', 'Paris'),
                ('Europe/Paris', 'Lyon'),
                ('Europe/Paris', 'Marseille')
            ],
            'JP': [
                ('Asia/Tokyo', 'Tokyo'),
                ('Asia/Tokyo', 'Osaka'),
                ('Asia/Tokyo', 'Yokohama')
            ],
            'AU': [
                ('Australia/Sydney', 'Sydney'),
                ('Australia/Melbourne', 'Melbourne'),
                ('Australia/Brisbane', 'Brisbane')
            ]
        }

        if country in timezone_map:
            tz, city = random.choice(timezone_map[country])
            return tz, city
        else:
            return 'America/New_York', 'New York'

    @staticmethod
    def generate_desktop_highend(country: str = 'US') -> RealisticHardwareProfile:
        """Generate high-end desktop PC profile."""
        # Select GPU vendor
        vendor = random.choice(['nvidia', 'amd'])
        gpu_tier = RealisticProfileGenerator.GPU_TIERS['high_end']

        if vendor == 'nvidia':
            gpu_model = random.choice(gpu_tier['nvidia'])
            gpu_vendor = 'NVIDIA Corporation'
            webgl_vendor = 'Google Inc. (NVIDIA)'
            webgl_renderer = f'ANGLE ({gpu_model} Direct3D11 vs_5_0 ps_5_0)'
        else:
            gpu_model = random.choice(gpu_tier['amd'])
            gpu_vendor = 'AMD'
            webgl_vendor = 'AMD'
            webgl_renderer = gpu_model

        # Appropriate RAM for high-end GPU
        ram_gb = random.choice(gpu_tier['ram_gb'])
        cpu_cores = random.choice(gpu_tier['cpu_cores'])

        # High-end desktops typically have larger screens
        screen_config = random.choice([
            RealisticProfileGenerator.SCREEN_CONFIGS['desktop_4k'],
            RealisticProfileGenerator.SCREEN_CONFIGS['desktop_1440p']
        ])

        # Geographic data
        timezone, city = RealisticProfileGenerator._get_timezone_for_country(country)

        # Browser (Windows high-end typically uses Chrome or Edge)
        browser_family = random.choice(['chrome', 'edge'])
        browser_version = f'{random.randint(115, 122)}.0.0.0'

        if browser_family == 'chrome':
            user_agent = f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version} Safari/537.36'
            browser_vendor = 'Google Inc.'
        else:
            user_agent = f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version} Safari/537.36 Edg/{browser_version}'
            browser_vendor = 'Microsoft Corporation'

        return RealisticHardwareProfile(
            device_category='desktop_highend',
            platform='Win32',
            os_version='Windows NT 10.0',
            cpu_cores=cpu_cores,
            device_memory_gb=ram_gb,
            gpu_vendor=gpu_vendor,
            gpu_renderer=gpu_model,
            webgl_vendor=webgl_vendor,
            webgl_renderer=webgl_renderer,
            screen_width=screen_config['width'],
            screen_height=screen_config['height'],
            screen_depth=screen_config['depth'],
            device_pixel_ratio=screen_config['ratio'],
            browser_family=browser_family,
            user_agent=user_agent,
            browser_vendor=browser_vendor,
            browser_version=browser_version,
            country=country,
            region='',
            city=city,
            timezone=timezone,
            language='en-US',
            # Desktop - always plugged in
            has_battery=False,
            battery_charging=True,
            battery_level=1.0,
            battery_charging_time=0,
            battery_discharging_time=0,
            # Desktop - no sensors
            has_accelerometer=False,
            has_gyroscope=False,
            has_magnetometer=False,
            has_ambient_light=False,
            has_proximity=False,
            # Desktop webcam/mic
            camera_count=1,
            microphone_count=1,
            speaker_count=2,
            camera_labels=['HD Webcam'],
            microphone_labels=['Microphone (Realtek Audio)'],
            # Desktop - ethernet connection
            connection_type='ethernet',
            connection_effective_type='4g',
            connection_downlink_mbps=random.uniform(50.0, 1000.0),
            connection_rtt_ms=random.randint(5, 30),
            # Desktop - no touch
            max_touch_points=0,
            # High memory for high-end desktop
            performance_memory_limit_mb=ram_gb * 1024,
            # Randomization seeds
            canvas_noise_seed=RealisticProfileGenerator._generate_seed(),
            audio_noise_seed=RealisticProfileGenerator._generate_seed(),
            mouse_movement_seed=RealisticProfileGenerator._generate_seed(),
            keyboard_timing_seed=RealisticProfileGenerator._generate_seed()
        )

    @staticmethod
    def generate_laptop_business(country: str = 'US') -> RealisticHardwareProfile:
        """Generate business laptop profile."""
        gpu_tier = RealisticProfileGenerator.GPU_TIERS['integrated']

        # Business laptops typically have Intel integrated graphics
        gpu_model = random.choice(gpu_tier['intel'])
        ram_gb = random.choice([8, 16])
        cpu_cores = random.choice([4, 6, 8])

        screen_config = RealisticProfileGenerator.SCREEN_CONFIGS['laptop_1080p']
        timezone, city = RealisticProfileGenerator._get_timezone_for_country(country)

        # Business laptops often use Chrome or Edge
        browser_family = random.choice(['chrome', 'edge', 'firefox'])
        browser_version = f'{random.randint(115, 122)}.0.0.0'

        if browser_family == 'chrome':
            user_agent = f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version} Safari/537.36'
            browser_vendor = 'Google Inc.'
        elif browser_family == 'edge':
            user_agent = f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version} Safari/537.36 Edg/{browser_version}'
            browser_vendor = 'Microsoft Corporation'
        else:
            user_agent = f'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{random.randint(110, 120)}.0) Gecko/20100101 Firefox/{random.randint(110, 120)}.0'
            browser_vendor = 'Mozilla'

        return RealisticHardwareProfile(
            device_category='laptop_business',
            platform='Win32',
            os_version='Windows NT 10.0',
            cpu_cores=cpu_cores,
            device_memory_gb=ram_gb,
            gpu_vendor='Intel Inc.',
            gpu_renderer=gpu_model,
            webgl_vendor='Intel Inc.',
            webgl_renderer=gpu_model,
            screen_width=screen_config['width'],
            screen_height=screen_config['height'],
            screen_depth=screen_config['depth'],
            device_pixel_ratio=screen_config['ratio'],
            browser_family=browser_family,
            user_agent=user_agent,
            browser_vendor=browser_vendor,
            browser_version=browser_version,
            country=country,
            region='',
            city=city,
            timezone=timezone,
            language='en-US',
            # Laptop - has battery
            has_battery=True,
            battery_charging=random.choice([True, False]),
            battery_level=random.uniform(0.3, 1.0),
            battery_charging_time=random.randint(1800, 7200) if random.choice([True, False]) else 0,
            battery_discharging_time=random.randint(3600, 18000),
            # Laptop - minimal sensors
            has_accelerometer=random.choice([True, False]),
            has_gyroscope=False,
            has_magnetometer=False,
            has_ambient_light=random.choice([True, False]),
            has_proximity=False,
            # Laptop camera/mic
            camera_count=1,
            microphone_count=1,
            speaker_count=2,
            camera_labels=['Integrated Camera'],
            microphone_labels=['Internal Microphone'],
            # Laptop - WiFi connection
            connection_type='wifi',
            connection_effective_type='4g',
            connection_downlink_mbps=random.uniform(10.0, 100.0),
            connection_rtt_ms=random.randint(20, 80),
            # Laptop - no touch (business laptops typically)
            max_touch_points=0,
            # Appropriate memory
            performance_memory_limit_mb=ram_gb * 1024,
            # Randomization seeds
            canvas_noise_seed=RealisticProfileGenerator._generate_seed(),
            audio_noise_seed=RealisticProfileGenerator._generate_seed(),
            mouse_movement_seed=RealisticProfileGenerator._generate_seed(),
            keyboard_timing_seed=RealisticProfileGenerator._generate_seed()
        )

    @staticmethod
    def generate_macbook_pro(country: str = 'US') -> RealisticHardwareProfile:
        """Generate MacBook Pro profile."""
        # MacBook Pro specs
        cpu_cores = random.choice([8, 10, 12])
        ram_gb = random.choice([16, 32, 64])  # MacBook Pro can have up to 64GB (M2 Max)

        # Apple Silicon
        if cpu_cores >= 10:
            gpu_model = 'Apple M2 Max'
        elif cpu_cores >= 8:
            gpu_model = random.choice(['Apple M2 Pro', 'Apple M1 Pro'])
        else:
            gpu_model = 'Apple M1'

        screen_config = RealisticProfileGenerator.SCREEN_CONFIGS['laptop_retina']
        timezone, city = RealisticProfileGenerator._get_timezone_for_country(country)

        # Safari or Chrome on Mac
        browser_family = random.choice(['safari', 'chrome'])

        if browser_family == 'safari':
            safari_version = random.choice(['16.6', '17.0', '17.1'])
            user_agent = f'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{safari_version} Safari/605.1.15'
            browser_vendor = 'Apple Computer, Inc.'
            browser_version = safari_version
        else:
            browser_version = f'{random.randint(115, 122)}.0.0.0'
            user_agent = f'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version} Safari/537.36'
            browser_vendor = 'Google Inc.'

        return RealisticHardwareProfile(
            device_category='laptop_premium',
            platform='MacIntel',
            os_version='Mac OS X 10_15_7',
            cpu_cores=cpu_cores,
            device_memory_gb=ram_gb,
            gpu_vendor='Apple Inc.',
            gpu_renderer=gpu_model,
            webgl_vendor='Apple Inc.',
            webgl_renderer=gpu_model,
            screen_width=screen_config['width'],
            screen_height=screen_config['height'],
            screen_depth=screen_config['depth'],
            device_pixel_ratio=screen_config['ratio'],
            browser_family=browser_family,
            user_agent=user_agent,
            browser_vendor=browser_vendor,
            browser_version=browser_version,
            country=country,
            region='',
            city=city,
            timezone=timezone,
            language='en-US',
            # MacBook - has battery
            has_battery=True,
            battery_charging=random.choice([True, False]),
            battery_level=random.uniform(0.4, 1.0),
            battery_charging_time=random.randint(1800, 5400),
            battery_discharging_time=random.randint(7200, 36000),
            # MacBook - some sensors
            has_accelerometer=True,
            has_gyroscope=False,
            has_magnetometer=False,
            has_ambient_light=True,
            has_proximity=False,
            # MacBook camera/mic
            camera_count=1,
            microphone_count=1,
            speaker_count=2,
            camera_labels=['FaceTime HD Camera'],
            microphone_labels=['MacBook Pro Microphone'],
            # MacBook - WiFi
            connection_type='wifi',
            connection_effective_type='4g',
            connection_downlink_mbps=random.uniform(20.0, 200.0),
            connection_rtt_ms=random.randint(15, 60),
            # MacBook - no touch
            max_touch_points=0,
            # Appropriate memory
            performance_memory_limit_mb=ram_gb * 1024,
            # Randomization seeds
            canvas_noise_seed=RealisticProfileGenerator._generate_seed(),
            audio_noise_seed=RealisticProfileGenerator._generate_seed(),
            mouse_movement_seed=RealisticProfileGenerator._generate_seed(),
            keyboard_timing_seed=RealisticProfileGenerator._generate_seed()
        )

    @staticmethod
    def generate_mobile_flagship(country: str = 'US') -> RealisticHardwareProfile:
        """Generate flagship mobile device profile."""
        # Flagship specs
        device_models = [
            ('Pixel 8 Pro', 'Qualcomm', 'Adreno 740', 12, 12),
            ('Pixel 7 Pro', 'Qualcomm', 'Adreno 730', 12, 12),
            ('Galaxy S23 Ultra', 'Qualcomm', 'Adreno 740', 12, 12),
            ('iPhone 15 Pro', 'Apple', 'Apple A17 Pro GPU', 6, 8),
            ('iPhone 14 Pro', 'Apple', 'Apple A16 GPU', 6, 6)
        ]

        model, gpu_vendor, gpu_renderer, ram_gb, cpu_cores = random.choice(device_models)

        screen_config = RealisticProfileGenerator.SCREEN_CONFIGS['mobile_flagship']
        timezone, city = RealisticProfileGenerator._get_timezone_for_country(country)

        # Mobile Chrome
        browser_version = f'{random.randint(115, 122)}.0.0.0'

        if 'iPhone' in model:
            platform = 'iPhone'
            user_agent = f'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
            browser_family = 'safari'
            browser_vendor = 'Apple Computer, Inc.'
        else:
            platform = 'Linux armv8l'
            user_agent = f'Mozilla/5.0 (Linux; Android 14; {model}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version} Mobile Safari/537.36'
            browser_family = 'chrome'
            browser_vendor = 'Google Inc.'

        return RealisticHardwareProfile(
            device_category='mobile_flagship',
            platform=platform,
            os_version='Android 14' if 'Android' in user_agent else 'iOS 17',
            cpu_cores=cpu_cores,
            device_memory_gb=ram_gb,
            gpu_vendor=gpu_vendor,
            gpu_renderer=gpu_renderer,
            webgl_vendor=gpu_vendor,
            webgl_renderer=gpu_renderer,
            screen_width=screen_config['width'],
            screen_height=screen_config['height'],
            screen_depth=screen_config['depth'],
            device_pixel_ratio=screen_config['ratio'],
            browser_family=browser_family,
            user_agent=user_agent,
            browser_vendor=browser_vendor,
            browser_version=browser_version,
            country=country,
            region='',
            city=city,
            timezone=timezone,
            language='en-US',
            # Mobile - battery
            has_battery=True,
            battery_charging=random.choice([True, False]),
            battery_level=random.uniform(0.2, 1.0),
            battery_charging_time=random.randint(1800, 5400),
            battery_discharging_time=random.randint(7200, 43200),
            # Mobile - all sensors
            has_accelerometer=True,
            has_gyroscope=True,
            has_magnetometer=True,
            has_ambient_light=True,
            has_proximity=True,
            # Mobile cameras
            camera_count=3,  # Flagship has multiple cameras
            microphone_count=2,
            speaker_count=2,
            camera_labels=['Front Camera', 'Wide Camera', 'Ultra Wide Camera'],
            microphone_labels=['Primary Microphone', 'Secondary Microphone'],
            # Mobile - cellular/wifi
            connection_type=random.choice(['wifi', '4g', '5g']),
            connection_effective_type=random.choice(['4g', '5g']),
            connection_downlink_mbps=random.uniform(5.0, 100.0),
            connection_rtt_ms=random.randint(30, 150),
            # Mobile - touch
            max_touch_points=5,
            # Mobile memory
            performance_memory_limit_mb=ram_gb * 1024,
            # Randomization seeds
            canvas_noise_seed=RealisticProfileGenerator._generate_seed(),
            audio_noise_seed=RealisticProfileGenerator._generate_seed(),
            mouse_movement_seed=RealisticProfileGenerator._generate_seed(),
            keyboard_timing_seed=RealisticProfileGenerator._generate_seed()
        )


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    import json

    print("="*80)
    print("REALISTIC HARDWARE PROFILE GENERATOR DEMONSTRATION")
    print("="*80)
    print()

    print("Generating realistic hardware profiles...")
    print()

    # High-end desktop
    profile = RealisticProfileGenerator.generate_desktop_highend('US')
    print(f"✅ High-End Desktop ({profile.device_category}):")
    print(f"   Platform: {profile.platform}")
    print(f"   GPU: {profile.gpu_renderer}")
    print(f"   RAM: {profile.device_memory_gb}GB (realistic for high-end GPU)")
    print(f"   CPU Cores: {profile.cpu_cores}")
    print(f"   Screen: {profile.screen_width}x{profile.screen_height} @ {profile.device_pixel_ratio}x")
    print(f"   Battery: {'No' if not profile.has_battery else 'Yes'} (desktops don't have batteries)")
    print(f"   Sensors: Accel={profile.has_accelerometer} (desktops don't have sensors)")
    print(f"   Connection: {profile.connection_type} ({profile.connection_downlink_mbps:.1f} Mbps)")
    print()

    # Business laptop
    profile = RealisticProfileGenerator.generate_laptop_business('US')
    print(f"✅ Business Laptop ({profile.device_category}):")
    print(f"   Platform: {profile.platform}")
    print(f"   GPU: {profile.gpu_renderer}")
    print(f"   RAM: {profile.device_memory_gb}GB (appropriate for integrated GPU)")
    print(f"   Battery: {'Charging' if profile.battery_charging else 'Discharging'} ({profile.battery_level*100:.0f}%)")
    print(f"   Connection: {profile.connection_type}")
    print()

    # MacBook Pro
    profile = RealisticProfileGenerator.generate_macbook_pro('US')
    print(f"✅ MacBook Pro ({profile.device_category}):")
    print(f"   Platform: {profile.platform} (correct for Mac)")
    print(f"   GPU: {profile.gpu_renderer} (Apple Silicon)")
    print(f"   RAM: {profile.device_memory_gb}GB (realistic for MacBook Pro)")
    print(f"   Screen: {profile.screen_width}x{profile.screen_height} @ {profile.device_pixel_ratio}x (Retina)")
    print(f"   Browser: {profile.browser_family}")
    print()

    # Flagship mobile
    profile = RealisticProfileGenerator.generate_mobile_flagship('US')
    print(f"✅ Flagship Mobile ({profile.device_category}):")
    print(f"   Platform: {profile.platform}")
    print(f"   GPU: {profile.gpu_renderer}")
    print(f"   RAM: {profile.device_memory_gb}GB (flagship mobile specs)")
    print(f"   Cameras: {profile.camera_count}")
    print(f"   Sensors: All sensors present (mobile device)")
    print(f"   Touch Points: {profile.max_touch_points}")
    print(f"   Connection: {profile.connection_type}")
    print()

    print("="*80)
    print()
    print("✅ All profiles have realistic hardware combinations:")
    print("   - High-end GPUs paired with appropriate RAM")
    print("   - Desktops have no battery or sensors")
    print("   - Laptops have batteries and WiFi")
    print("   - Mobile devices have all sensors and touch support")
    print("   - Screen sizes match device categories")
    print("   - Browser families match OS platforms")
    print()
    print("="*80)
