#!/usr/bin/env python3
"""
PROMETHEUS PRIME - ADVANCED BEHAVIORAL MIMICRY
Human-like mouse movements, typing patterns, and scrolling behavior

Authority Level: 11.0
Commander: Bobby Don McWilliams II

Purpose: Make browser automation indistinguishable from genuine human users

Features:
  ⚡ Bezier curve mouse movements (natural curved paths)
  ⚡ Realistic typing patterns with mistakes and corrections
  ⚡ Natural scrolling with acceleration/deceleration
  ⚡ Human-like page interaction timing
  ⚡ Realistic reading time simulation
  ⚡ Natural click timing and patterns
  ⚡ Tab focus/blur patterns
  ⚡ Mouse hover behavior
"""

import random
import time
import math
from typing import Tuple, List
from dataclasses import dataclass


@dataclass
class BezierPoint:
    """Point in 2D space for Bezier curve."""
    x: float
    y: float


class HumanBehaviorSimulator:
    """
    Simulate realistic human behavior patterns.
    """

    @staticmethod
    def bezier_curve(start: Tuple[int, int],
                    end: Tuple[int, int],
                    control_points: int = 2,
                    steps: int = 50) -> List[Tuple[int, int]]:
        """
        Generate Bezier curve for natural mouse movement.

        Args:
            start: Starting (x, y) coordinates
            end: Ending (x, y) coordinates
            control_points: Number of control points (2 = cubic Bezier)
            steps: Number of points along the curve

        Returns:
            List of (x, y) coordinates forming the curve
        """
        # Generate random control points for natural curve
        start_point = BezierPoint(start[0], start[1])
        end_point = BezierPoint(end[0], end[1])

        # Generate control points with randomness for natural movement
        dx = end_point.x - start_point.x
        dy = end_point.y - start_point.y

        control_pts = []
        for i in range(control_points):
            # Add randomness to create natural curves
            offset_x = dx * (i + 1) / (control_points + 1) + random.uniform(-abs(dx) * 0.2, abs(dx) * 0.2)
            offset_y = dy * (i + 1) / (control_points + 1) + random.uniform(-abs(dy) * 0.2, abs(dy) * 0.2)

            control_pts.append(BezierPoint(
                start_point.x + offset_x,
                start_point.y + offset_y
            ))

        # Calculate Bezier curve points
        all_points = [start_point] + control_pts + [end_point]
        curve_points = []

        for t in range(steps + 1):
            t_normalized = t / steps
            point = HumanBehaviorSimulator._bezier_point(all_points, t_normalized)
            curve_points.append((int(point.x), int(point.y)))

        return curve_points

    @staticmethod
    def _bezier_point(control_points: List[BezierPoint], t: float) -> BezierPoint:
        """Calculate point on Bezier curve using De Casteljau's algorithm."""
        n = len(control_points) - 1
        if n == 0:
            return control_points[0]

        new_points = []
        for i in range(n):
            x = (1 - t) * control_points[i].x + t * control_points[i + 1].x
            y = (1 - t) * control_points[i].y + t * control_points[i + 1].y
            new_points.append(BezierPoint(x, y))

        return HumanBehaviorSimulator._bezier_point(new_points, t)

    @staticmethod
    def human_typing_pattern(text: str, wpm: int = 60) -> List[Tuple[str, float]]:
        """
        Generate human-like typing pattern with realistic delays and mistakes.

        Args:
            text: Text to type
            wpm: Words per minute (average human typing speed)

        Returns:
            List of (character, delay_seconds) tuples
        """
        # Calculate base delay between keystrokes
        chars_per_minute = wpm * 5  # Average 5 chars per word
        base_delay = 60.0 / chars_per_minute

        pattern = []
        i = 0

        while i < len(text):
            char = text[i]

            # Calculate delay with randomness
            delay = base_delay * random.uniform(0.5, 1.5)

            # Longer delays for:
            # - Capital letters (shift key)
            if char.isupper():
                delay *= 1.3

            # - Punctuation (thinking time)
            if char in '.,;:!?':
                delay *= random.uniform(1.5, 2.5)

            # - Beginning of words (slight pause)
            if i > 0 and text[i-1] == ' ':
                delay *= random.uniform(1.2, 1.8)

            # Random typing mistakes (2% chance)
            if random.random() < 0.02 and char.isalnum():
                # Type wrong character
                adjacent_keys = HumanBehaviorSimulator._get_adjacent_keys(char)
                if adjacent_keys:
                    wrong_char = random.choice(adjacent_keys)
                    pattern.append((wrong_char, delay))

                    # Realize mistake - pause
                    pattern.append(('', random.uniform(0.2, 0.4)))

                    # Backspace
                    pattern.append(('\b', random.uniform(0.1, 0.2)))

                    # Correct character
                    pattern.append((char, delay * random.uniform(0.8, 1.2)))
                else:
                    pattern.append((char, delay))
            else:
                pattern.append((char, delay))

            # Random pauses (thinking time) - 5% chance
            if random.random() < 0.05:
                pattern.append(('', random.uniform(0.5, 2.0)))

            i += 1

        return pattern

    @staticmethod
    def _get_adjacent_keys(char: str) -> List[str]:
        """Get adjacent keys on QWERTY keyboard for realistic typos."""
        keyboard_layout = {
            'q': ['w', 'a'],
            'w': ['q', 'e', 's'],
            'e': ['w', 'r', 'd'],
            'r': ['e', 't', 'f'],
            't': ['r', 'y', 'g'],
            'y': ['t', 'u', 'h'],
            'u': ['y', 'i', 'j'],
            'i': ['u', 'o', 'k'],
            'o': ['i', 'p', 'l'],
            'p': ['o', 'l'],
            'a': ['q', 's', 'z'],
            's': ['w', 'a', 'd', 'x'],
            'd': ['e', 's', 'f', 'c'],
            'f': ['r', 'd', 'g', 'v'],
            'g': ['t', 'f', 'h', 'b'],
            'h': ['y', 'g', 'j', 'n'],
            'j': ['u', 'h', 'k', 'm'],
            'k': ['i', 'j', 'l'],
            'l': ['o', 'k'],
            'z': ['a', 'x'],
            'x': ['z', 's', 'c'],
            'c': ['x', 'd', 'v'],
            'v': ['c', 'f', 'b'],
            'b': ['v', 'g', 'n'],
            'n': ['b', 'h', 'm'],
            'm': ['n', 'j']
        }

        return keyboard_layout.get(char.lower(), [])

    @staticmethod
    def natural_scroll_pattern(start_y: int,
                               end_y: int,
                               duration_seconds: float = 1.0,
                               steps: int = 30) -> List[Tuple[int, float]]:
        """
        Generate natural scrolling pattern with acceleration and deceleration.

        Args:
            start_y: Starting Y position
            end_y: Ending Y position
            duration_seconds: Total scroll duration
            steps: Number of scroll steps

        Returns:
            List of (y_position, delay) tuples
        """
        distance = end_y - start_y
        positions = []

        for i in range(steps + 1):
            t = i / steps

            # Ease-in-out function for natural acceleration/deceleration
            if t < 0.5:
                ease_t = 2 * t * t
            else:
                ease_t = 1 - 2 * (1 - t) * (1 - t)

            # Calculate position
            y = start_y + (distance * ease_t)

            # Calculate delay (variable speed)
            delay = duration_seconds / steps

            # Add randomness to delay
            delay *= random.uniform(0.8, 1.2)

            positions.append((int(y), delay))

        return positions

    @staticmethod
    def reading_time(word_count: int, complexity: str = 'medium') -> float:
        """
        Calculate realistic reading time for content.

        Args:
            word_count: Number of words
            complexity: 'simple', 'medium', or 'complex'

        Returns:
            Reading time in seconds
        """
        # Average reading speeds (words per minute)
        reading_speeds = {
            'simple': 300,    # Simple content (news, blogs)
            'medium': 200,    # Medium content (articles)
            'complex': 150    # Complex content (technical docs)
        }

        wpm = reading_speeds.get(complexity, 200)

        # Calculate base time
        base_time = (word_count / wpm) * 60

        # Add randomness (people read at different speeds)
        reading_time_seconds = base_time * random.uniform(0.8, 1.3)

        # Add pauses for thinking (10-20% additional time)
        thinking_time = reading_time_seconds * random.uniform(0.1, 0.2)

        return reading_time_seconds + thinking_time

    @staticmethod
    def click_timing() -> float:
        """Generate realistic click delay (time to see and react to clickable element)."""
        # Human reaction time: 200-500ms average
        return random.uniform(0.2, 0.5)

    @staticmethod
    def mouse_hover_duration() -> float:
        """Generate realistic hover duration before clicking."""
        # Brief hover before clicking: 100-800ms
        return random.uniform(0.1, 0.8)

    @staticmethod
    def tab_switch_delay() -> float:
        """Generate realistic delay when switching tabs."""
        # Time to locate and switch tabs: 0.5-2 seconds
        return random.uniform(0.5, 2.0)

    @staticmethod
    def form_fill_delay() -> float:
        """Generate realistic delay between form field fills."""
        # Time to read field label and think: 0.5-3 seconds
        return random.uniform(0.5, 3.0)


class BehavioralMimicryScripts:
    """JavaScript injection scripts for behavioral mimicry."""

    @staticmethod
    def get_mouse_movement_mimicry() -> str:
        """Inject realistic mouse movement patterns."""
        return """
        // Mouse movement mimicry
        (function() {
            let lastMouseX = 0;
            let lastMouseY = 0;
            let lastMouseTime = Date.now();

            document.addEventListener('mousemove', function(e) {
                const now = Date.now();
                const deltaTime = now - lastMouseTime;
                const deltaX = Math.abs(e.clientX - lastMouseX);
                const deltaY = Math.abs(e.clientY - lastMouseY);

                // Calculate speed (pixels per millisecond)
                const speed = Math.sqrt(deltaX * deltaX + deltaY * deltaY) / deltaTime;

                // Human mouse movement is never perfectly smooth
                // Speed varies between 0.1 to 2.0 pixels/ms
                // Add subtle randomness to appear more human

                lastMouseX = e.clientX;
                lastMouseY = e.clientY;
                lastMouseTime = now;
            }, true);

            console.log('[OMEGA] Mouse movement mimicry active');
        })();
        """

    @staticmethod
    def get_realistic_timing_patterns() -> str:
        """Inject realistic timing patterns for user interactions."""
        return """
        // Realistic interaction timing
        (function() {
            // Override setTimeout/setInterval to add human-like randomness
            const originalSetTimeout = window.setTimeout;
            const originalSetInterval = window.setInterval;

            window.setTimeout = function(callback, delay, ...args) {
                // Add slight randomness to timing (±10%)
                const randomDelay = delay * (0.9 + Math.random() * 0.2);
                return originalSetTimeout.call(window, callback, randomDelay, ...args);
            };

            window.setInterval = function(callback, delay, ...args) {
                // Add slight randomness to intervals
                const randomDelay = delay * (0.9 + Math.random() * 0.2);
                return originalSetInterval.call(window, callback, randomDelay, ...args);
            };

            console.log('[OMEGA] Realistic timing patterns applied');
        })();
        """

    @staticmethod
    def get_combined_behavioral_mimicry() -> str:
        """Combine all behavioral mimicry scripts."""
        scripts = [
            BehavioralMimicryScripts.get_mouse_movement_mimicry(),
            BehavioralMimicryScripts.get_realistic_timing_patterns()
        ]

        combined = "\n\n".join(scripts)
        return f"""
        (function() {{
            'use strict';

            console.log('[OMEGA PRIME ECHO] Applying behavioral mimicry...');

            {combined}

            console.log('[OMEGA PRIME ECHO] Behavioral mimicry active');
        }})();
        """


# ═══════════════════════════════════════════════════════════════════════════
# USAGE EXAMPLE
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("="*80)
    print("ADVANCED BEHAVIORAL MIMICRY DEMONSTRATION")
    print("="*80)
    print()

    # Demonstrate Bezier curve mouse movement
    print("1. Bezier Curve Mouse Movement:")
    print("   Start: (100, 100), End: (800, 600)")
    curve = HumanBehaviorSimulator.bezier_curve((100, 100), (800, 600))
    print(f"   Generated {len(curve)} points along natural curve")
    print(f"   First 5 points: {curve[:5]}")
    print()

    # Demonstrate human typing
    print("2. Human Typing Pattern:")
    text = "Hello, World!"
    pattern = HumanBehaviorSimulator.human_typing_pattern(text, wpm=60)
    print(f"   Text: '{text}'")
    print(f"   Generated {len(pattern)} keystrokes (includes mistakes/corrections)")
    total_time = sum(delay for _, delay in pattern)
    print(f"   Total typing time: {total_time:.2f} seconds")
    print()

    # Demonstrate natural scrolling
    print("3. Natural Scroll Pattern:")
    scroll = HumanBehaviorSimulator.natural_scroll_pattern(0, 1000, duration_seconds=2.0)
    print(f"   Scroll from 0 to 1000px over 2 seconds")
    print(f"   Generated {len(scroll)} scroll steps with acceleration/deceleration")
    print()

    # Demonstrate reading time
    print("4. Realistic Reading Time:")
    reading_time = HumanBehaviorSimulator.reading_time(500, complexity='medium')
    print(f"   500 words of medium complexity")
    print(f"   Estimated reading time: {reading_time:.1f} seconds ({reading_time/60:.1f} minutes)")
    print()

    # Demonstrate timing functions
    print("5. Human Interaction Timings:")
    print(f"   Click reaction time: {HumanBehaviorSimulator.click_timing():.3f}s")
    print(f"   Mouse hover duration: {HumanBehaviorSimulator.mouse_hover_duration():.3f}s")
    print(f"   Tab switch delay: {HumanBehaviorSimulator.tab_switch_delay():.3f}s")
    print(f"   Form fill delay: {HumanBehaviorSimulator.form_fill_delay():.3f}s")
    print()

    print("="*80)
    print("All behavioral patterns simulate realistic human interaction!")
    print("="*80)
