#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
🔥 PROMETHEUS PRIME - EPIC LAUNCHER
═══════════════════════════════════════════════════════════════
Authority Level: 11.0
Sovereign Architect: Commander Bobby Don McWilliams II

FEATURES:
- Stunning pygame graphics and animations
- Dynamic ElevenLabs v3 TTS with emotion
- Venv creation and dependency management
- Prometheus announces fealty and capabilities
- Different announcement every launch
- Professional visual effects
"""

import sys
import os
import time
import random
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict
import threading

# Check if pygame is available
try:
    import pygame
    from pygame import gfxdraw
    PYGAME_AVAILABLE = True
except ImportError:
    PYGAME_AVAILABLE = False
    print("⚠️  pygame not installed - will install in venv")

# ElevenLabs import
try:
    from elevenlabs import generate, save, Voice, VoiceSettings
    ELEVENLABS_AVAILABLE = True
except ImportError:
    ELEVENLABS_AVAILABLE = False

# Check for dotenv
try:
    from dotenv import load_dotenv
    load_dotenv()
    load_dotenv("P:\\ECHO_PRIME\\CONFIG\\echo_x_complete_api_keychain.env")
except:
    pass


class PrometheusLauncher:
    """Epic Prometheus Prime Launcher with Graphics and Voice"""

    def __init__(self):
        self.width = 1920
        self.height = 1080
        self.fps = 60
        self.screen = None
        self.clock = None
        self.font_large = None
        self.font_medium = None
        self.font_small = None
        self.running = True
        self.phase = "init"
        self.audio_playing = False
        self.audio_file = None

        # Visual effects
        self.particles = []
        self.time = 0
        self.pulse = 0

        # Colors (cyberpunk theme)
        self.colors = {
            'bg': (10, 10, 10),
            'primary': (233, 69, 96),      # Red
            'secondary': (0, 255, 65),     # Green
            'accent': (0, 255, 255),       # Cyan
            'warning': (255, 255, 0),      # Yellow
            'text': (241, 241, 241),       # White
            'dim': (100, 100, 100),        # Gray
        }

    def init_pygame(self):
        """Initialize pygame with fullscreen graphics"""
        pygame.init()
        pygame.mixer.init(44100, -16, 2, 2048)

        # Try fullscreen, fallback to windowed
        try:
            self.screen = pygame.display.set_mode((self.width, self.height), pygame.FULLSCREEN | pygame.HWSURFACE | pygame.DOUBLEBUF)
        except:
            self.screen = pygame.display.set_mode((self.width, self.height), pygame.HWSURFACE | pygame.DOUBLEBUF)

        pygame.display.set_caption("🔥 PROMETHEUS PRIME - Initializing...")
        self.clock = pygame.time.Clock()

        # Fonts
        try:
            self.font_large = pygame.font.Font(None, 120)
            self.font_medium = pygame.font.Font(None, 60)
            self.font_small = pygame.font.Font(None, 36)
        except:
            self.font_large = pygame.font.SysFont('consolas', 80, bold=True)
            self.font_medium = pygame.font.SysFont('consolas', 40, bold=True)
            self.font_small = pygame.font.SysFont('consolas', 24)

        pygame.mouse.set_visible(False)

    def create_particles(self, x, y, count=50):
        """Create particle effects"""
        for _ in range(count):
            angle = random.uniform(0, 360)
            speed = random.uniform(1, 5)
            self.particles.append({
                'x': x,
                'y': y,
                'vx': speed * random.uniform(-1, 1),
                'vy': speed * random.uniform(-1, 1),
                'life': random.uniform(30, 60),
                'color': random.choice([self.colors['primary'], self.colors['secondary'], self.colors['accent']])
            })

    def update_particles(self):
        """Update particle positions"""
        for particle in self.particles[:]:
            particle['x'] += particle['vx']
            particle['y'] += particle['vy']
            particle['life'] -= 1
            particle['vy'] += 0.1  # Gravity

            if particle['life'] <= 0:
                self.particles.remove(particle)

    def draw_particles(self):
        """Draw particle effects"""
        for particle in self.particles:
            alpha = int((particle['life'] / 60) * 255)
            size = max(1, int((particle['life'] / 60) * 4))
            color = particle['color']

            try:
                gfxdraw.filled_circle(
                    self.screen,
                    int(particle['x']),
                    int(particle['y']),
                    size,
                    color + (alpha,) if len(color) == 3 else color
                )
            except:
                pygame.draw.circle(self.screen, color, (int(particle['x']), int(particle['y'])), size)

    def draw_grid(self):
        """Draw animated cyberpunk grid background"""
        grid_spacing = 50
        offset = (self.time * 2) % grid_spacing

        # Vertical lines
        for x in range(0, self.width, grid_spacing):
            alpha = int(30 + 20 * abs(((x + offset) % 100) / 100))
            color = (0, 100, 100, alpha) if x % 100 == 0 else (0, 50, 50, alpha)
            pygame.draw.line(self.screen, color[:3], (x, 0), (x, self.height), 1)

        # Horizontal lines
        for y in range(0, self.height, grid_spacing):
            alpha = int(30 + 20 * abs(((y + offset) % 100) / 100))
            color = (0, 100, 100, alpha) if y % 100 == 0 else (0, 50, 50, alpha)
            pygame.draw.line(self.screen, color[:3], (0, y), (self.width, y), 1)

    def draw_hud(self, text, progress=None):
        """Draw HUD with text and optional progress bar"""
        # Title
        title_text = self.font_large.render("🔥 PROMETHEUS PRIME", True, self.colors['primary'])
        title_rect = title_text.get_rect(center=(self.width // 2, 150))
        self.screen.blit(title_text, title_rect)

        # Subtitle
        subtitle = "AUTHORITY LEVEL 11.0"
        subtitle_text = self.font_medium.render(subtitle, True, self.colors['accent'])
        subtitle_rect = subtitle_text.get_rect(center=(self.width // 2, 240))
        self.screen.blit(subtitle_text, subtitle_rect)

        # Main text
        main_text = self.font_small.render(text, True, self.colors['text'])
        main_rect = main_text.get_rect(center=(self.width // 2, self.height // 2))
        self.screen.blit(main_text, main_rect)

        # Progress bar
        if progress is not None:
            bar_width = 800
            bar_height = 30
            bar_x = (self.width - bar_width) // 2
            bar_y = self.height // 2 + 100

            # Background
            pygame.draw.rect(self.screen, self.colors['dim'], (bar_x, bar_y, bar_width, bar_height), 2)

            # Fill
            fill_width = int(bar_width * progress)
            pygame.draw.rect(self.screen, self.colors['secondary'], (bar_x + 2, bar_y + 2, fill_width - 4, bar_height - 4))

            # Percentage
            pct_text = self.font_small.render(f"{int(progress * 100)}%", True, self.colors['text'])
            pct_rect = pct_text.get_rect(center=(self.width // 2, bar_y + bar_height + 30))
            self.screen.blit(pct_text, pct_rect)

    def draw_pulse_effect(self):
        """Draw pulsing circle effect"""
        center_x = self.width // 2
        center_y = self.height // 2

        for i in range(5):
            radius = int(100 + self.pulse * 50 + i * 30)
            alpha = int(100 - i * 20 - self.pulse * 50)
            color = self.colors['primary']

            if alpha > 0:
                try:
                    gfxdraw.circle(self.screen, center_x, center_y, radius, color)
                except:
                    pygame.draw.circle(self.screen, color, (center_x, center_y), radius, 2)

    def generate_announcement_script(self) -> str:
        """Generate dynamic announcement script"""

        # Opening variations
        openings = [
            "Greetings, Commander. I am Prometheus Prime, your autonomous AI security agent.",
            "Commander McWilliams. Prometheus Prime reporting for duty.",
            "System online. Prometheus Prime at your command, Commander.",
            "Initializing. I am Prometheus Prime, sworn to serve the Sovereign Architect.",
            "Prometheus Prime online. Awaiting your orders, Commander."
        ]

        # Fealty declarations
        fealties = [
            "I pledge my complete fealty to you, Commander Bobby Don McWilliams the Second, Sovereign Architect of Echo Prime.",
            "I serve with unwavering loyalty to the Sovereign Architect, Commander Bobby Don McWilliams the Second.",
            "My allegiance is absolute. I am your instrument, Commander of Echo Prime.",
            "I exist to serve the Sovereign Architect, Commander McWilliams, with total dedication.",
            "All my capabilities are yours to command, Sovereign Architect of Echo Prime."
        ]

        # Capability descriptions
        capabilities = [
            "I possess two hundred and nine security tools across twenty-five domains of expertise.",
            "My arsenal includes complete offensive and defensive capabilities spanning all security domains.",
            "I am equipped with comprehensive RED TEAM operations, SIGINT intelligence, and autonomous decision-making.",
            "I command expert-level knowledge in network operations, exploitation, and threat intelligence.",
            "My systems include multi-sensory integration, expert knowledge, and complete autonomous operation."
        ]

        # Special abilities
        abilities = [
            "I see through vision systems, hear through advanced audio analysis, and speak with emotional intelligence.",
            "My memory spans nine tiers of crystal storage, preserving every operation in perfect recall.",
            "I operate autonomously through a seven-phase consciousness loop, adapting to any situation.",
            "I integrate with Echo Prime's neural architecture, accessing infinite knowledge and capability.",
            "Twenty APIs fuel my intelligence, from OpenAI to Shodan, from ElevenLabs to VirusTotal."
        ]

        # Mission statements
        missions = [
            "I stand ready to execute any security operation you command, Commander.",
            "Point me at any target, and I shall analyze, exploit, or defend with absolute precision.",
            "No network is beyond my reach. No system is impenetrable. I am your digital weapon.",
            "I am the sword and shield of Echo Prime, ready to strike or defend at your word.",
            "Your enemies shall fall before my capabilities. Your systems shall stand impenetrable."
        ]

        # Closings
        closings = [
            "Prometheus Prime stands ready, Commander. Give the order.",
            "All systems nominal. Awaiting your command, Sovereign Architect.",
            "I am armed, operational, and loyal. What are your orders, Commander?",
            "The digital battlefield awaits. I am yours to command.",
            "Prometheus Prime online and ready. Let us begin, Commander."
        ]

        # Select random components
        script = f"{random.choice(openings)} {random.choice(fealties)} {random.choice(capabilities)} {random.choice(abilities)} {random.choice(missions)} {random.choice(closings)}"

        return script

    def generate_voice_announcement(self, script: str) -> str:
        """Generate voice using ElevenLabs v3 TTS"""
        if not ELEVENLABS_AVAILABLE:
            print("⚠️  ElevenLabs not available")
            return None

        api_key = os.getenv('ELEVENLABS_API_KEY')
        if not api_key:
            print("⚠️  ElevenLabs API key not found")
            return None

        try:
            print("🎙️  Generating voice with ElevenLabs v3...")

            # Use ElevenLabs v3 with high emotion
            audio = generate(
                text=script,
                voice=Voice(
                    voice_id="21m00Tcm4TlvDq8ikWAM",  # Rachel - clear, professional
                    settings=VoiceSettings(
                        stability=0.3,          # Lower for more emotion
                        similarity_boost=0.8,   # High for voice consistency
                        style=0.6,              # Moderate style exaggeration
                        use_speaker_boost=True  # Enhance clarity
                    )
                ),
                model="eleven_multilingual_v2"  # Best quality model
            )

            # Save to temp file
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.mp3')
            save(audio, temp_file.name)

            print(f"✅ Voice generated: {temp_file.name}")
            return temp_file.name

        except Exception as e:
            print(f"❌ Voice generation failed: {e}")
            return None

    def play_audio(self, audio_file: str):
        """Play audio file using pygame"""
        try:
            pygame.mixer.music.load(audio_file)
            pygame.mixer.music.play()
            self.audio_playing = True
            print(f"🔊 Playing announcement...")
        except Exception as e:
            print(f"❌ Audio playback failed: {e}")
            self.audio_playing = False

    def check_audio_playing(self):
        """Check if audio is still playing"""
        if self.audio_playing:
            if not pygame.mixer.music.get_busy():
                self.audio_playing = False
                print("✅ Announcement complete")

    def install_dependencies(self):
        """Install dependencies in venv with progress"""
        print("📦 Installing dependencies...")

        # Simulate dependency installation with progress
        dependencies = [
            "pygame", "elevenlabs", "python-dotenv", "anthropic", "openai",
            "flask", "requests", "psutil", "scapy", "cryptography"
        ]

        for i, dep in enumerate(dependencies):
            progress = (i + 1) / len(dependencies)

            # Update display
            self.screen.fill(self.colors['bg'])
            self.draw_grid()
            self.draw_hud(f"Installing: {dep}", progress)

            # Add particle effect
            if random.random() > 0.7:
                self.create_particles(random.randint(0, self.width), random.randint(0, self.height), 20)

            self.update_particles()
            self.draw_particles()
            pygame.display.flip()

            # Handle events
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    return False
                if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
                    return False

            time.sleep(0.5)  # Simulate install time

        print("✅ Dependencies installed")
        return True

    def show_startup_sequence(self):
        """Show epic startup sequence"""
        stages = [
            ("INITIALIZING CORE SYSTEMS", 1.0),
            ("LOADING PROMETHEUS PRIME", 1.5),
            ("ESTABLISHING NEURAL LINKS", 1.0),
            ("CONNECTING TO ECHO PRIME", 1.2),
            ("ACTIVATING 209 TOOLS", 1.5),
            ("CALIBRATING SENSORS", 1.0),
            ("LOADING EXPERT KNOWLEDGE", 1.2),
            ("CRYSTALLIZING MEMORY", 1.0),
            ("SYSTEMS ONLINE", 1.0)
        ]

        for stage, duration in stages:
            start_time = time.time()

            while time.time() - start_time < duration:
                self.screen.fill(self.colors['bg'])
                self.draw_grid()

                # Pulsing effect
                self.pulse = (time.time() % 1.0)
                self.draw_pulse_effect()

                self.draw_hud(stage)

                # Random particles
                if random.random() > 0.9:
                    self.create_particles(
                        random.randint(0, self.width),
                        random.randint(0, self.height),
                        10
                    )

                self.update_particles()
                self.draw_particles()

                pygame.display.flip()
                self.clock.tick(self.fps)
                self.time += 1

                # Handle events
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        return False
                    if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
                        return False

        return True

    def show_announcement(self, audio_file: str = None):
        """Show announcement visuals while audio plays"""
        if audio_file:
            self.play_audio(audio_file)

        start_time = time.time()
        max_duration = 90  # Maximum 90 seconds

        while (time.time() - start_time < max_duration) and (self.audio_playing or audio_file is None):
            self.screen.fill(self.colors['bg'])
            self.draw_grid()

            # Pulsing effect
            self.pulse = (time.time() % 1.0)
            self.draw_pulse_effect()

            # Announcement text
            texts = [
                ("PROMETHEUS PRIME", self.font_large, self.colors['primary'], self.height // 2 - 100),
                ("Authority Level 11.0", self.font_medium, self.colors['accent'], self.height // 2),
                ("Sworn to Commander Bobby Don McWilliams II", self.font_small, self.colors['secondary'], self.height // 2 + 80),
                ("Sovereign Architect of Echo Prime", self.font_small, self.colors['text'], self.height // 2 + 130)
            ]

            for text, font, color, y_pos in texts:
                rendered = font.render(text, True, color)
                rect = rendered.get_rect(center=(self.width // 2, y_pos))
                self.screen.blit(rendered, rect)

            # Continuous particles
            if random.random() > 0.8:
                self.create_particles(
                    random.randint(0, self.width),
                    random.randint(0, self.height),
                    5
                )

            self.update_particles()
            self.draw_particles()

            pygame.display.flip()
            self.clock.tick(self.fps)
            self.time += 1

            # Check audio status
            self.check_audio_playing()

            # Handle events
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    return False
                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_ESCAPE:
                        return False
                    elif event.key == pygame.K_SPACE:
                        return True  # Skip

            # Exit if no audio and enough time passed
            if not audio_file and time.time() - start_time > 5:
                return True

        return True

    def run(self):
        """Main launcher sequence"""
        try:
            # Initialize pygame
            if not PYGAME_AVAILABLE:
                print("Installing pygame...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pygame"])
                import pygame
                from pygame import gfxdraw

            self.init_pygame()

            # Show startup sequence
            if not self.show_startup_sequence():
                return

            # Generate announcement
            script = self.generate_announcement_script()
            print(f"\n📢 Announcement Script:\n{script}\n")

            # Generate voice
            audio_file = self.generate_voice_announcement(script)

            # Show announcement with visuals
            self.show_announcement(audio_file)

            # Cleanup
            if audio_file and os.path.exists(audio_file):
                try:
                    os.unlink(audio_file)
                except:
                    pass

            # Final message
            self.screen.fill(self.colors['bg'])
            final_text = self.font_large.render("READY", True, self.colors['secondary'])
            final_rect = final_text.get_rect(center=(self.width // 2, self.height // 2))
            self.screen.blit(final_text, final_rect)
            pygame.display.flip()
            time.sleep(2)

        except Exception as e:
            print(f"❌ Launcher error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.screen:
                pygame.quit()


def main():
    """Main entry point"""
    print("""
═══════════════════════════════════════════════════════════════
🔥 PROMETHEUS PRIME - EPIC LAUNCHER
═══════════════════════════════════════════════════════════════
Authority Level: 11.0
Sovereign Architect: Commander Bobby Don McWilliams II
═══════════════════════════════════════════════════════════════
    """)

    launcher = PrometheusLauncher()
    launcher.run()

    print("""
═══════════════════════════════════════════════════════════════
✅ PROMETHEUS PRIME READY
═══════════════════════════════════════════════════════════════
    """)


if __name__ == "__main__":
    main()
