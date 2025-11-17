#!/usr/bin/env python3
"""
PROMETHEUS PRIME - BROWSER FINGERPRINT TESTER
Test and validate browser fingerprint spoofing effectiveness

Authority Level: 11.0
Commander: Bobby Don McWilliams II

Tests:
  - Canvas fingerprint
  - WebGL fingerprint
  - Audio context fingerprint
  - Font fingerprint
  - Screen resolution
  - Hardware concurrency
  - User-Agent
  - Timezone
  - Language
  - WebRTC leaks
"""

import json
import hashlib
from typing import Dict, List


class FingerprintTester:
    """
    Browser fingerprint testing utility.
    Validates anti-detect browser effectiveness.
    """

    def __init__(self):
        """Initialize fingerprint tester."""
        self.test_results = {}

    def test_all(self, driver) -> Dict:
        """
        Run all fingerprint tests.

        Args:
            driver: Selenium WebDriver instance

        Returns:
            Dictionary of test results
        """
        results = {}

        results['canvas'] = self.test_canvas(driver)
        results['webgl'] = self.test_webgl(driver)
        results['audio'] = self.test_audio(driver)
        results['fonts'] = self.test_fonts(driver)
        results['screen'] = self.test_screen(driver)
        results['hardware'] = self.test_hardware(driver)
        results['navigator'] = self.test_navigator(driver)
        results['timezone'] = self.test_timezone(driver)
        results['webrtc'] = self.test_webrtc(driver)

        # Calculate fingerprint hash
        fingerprint_str = json.dumps(results, sort_keys=True)
        results['fingerprint_hash'] = hashlib.sha256(fingerprint_str.encode()).hexdigest()

        return results

    def test_canvas(self, driver) -> Dict:
        """Test canvas fingerprint."""
        script = """
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('Prometheus Prime', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('Prometheus Prime', 4, 17);
        return canvas.toDataURL();
        """
        canvas_data = driver.execute_script(script)
        canvas_hash = hashlib.md5(canvas_data.encode()).hexdigest()

        return {
            'hash': canvas_hash,
            'length': len(canvas_data)
        }

    def test_webgl(self, driver) -> Dict:
        """Test WebGL fingerprint."""
        script = """
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        return {
            vendor: gl.getParameter(gl.VENDOR),
            renderer: gl.getParameter(gl.RENDERER),
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            unmaskedVendor: gl.getParameter(gl.getExtension('WEBGL_debug_renderer_info').UNMASKED_VENDOR_WEBGL),
            unmaskedRenderer: gl.getParameter(gl.getExtension('WEBGL_debug_renderer_info').UNMASKED_RENDERER_WEBGL)
        };
        """
        try:
            webgl_data = driver.execute_script(script)
            return webgl_data
        except:
            return {'error': 'WebGL not available'}

    def test_audio(self, driver) -> Dict:
        """Test audio context fingerprint."""
        script = """
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return {error: 'AudioContext not available'};

        const context = new AudioContext();
        const oscillator = context.createOscillator();
        const analyser = context.createAnalyser();
        const gainNode = context.createGain();
        const scriptProcessor = context.createScriptProcessor(4096, 1, 1);

        gainNode.gain.value = 0;
        oscillator.connect(analyser);
        analyser.connect(scriptProcessor);
        scriptProcessor.connect(gainNode);
        gainNode.connect(context.destination);

        oscillator.start(0);

        const audioData = [];
        scriptProcessor.onaudioprocess = function(event) {
            const output = event.outputBuffer.getChannelData(0);
            for (let i = 0; i < output.length; i++) {
                audioData.push(output[i]);
            }
            if (audioData.length > 1000) {
                oscillator.stop();
            }
        };

        return {
            sampleRate: context.sampleRate,
            maxChannelCount: context.destination.maxChannelCount,
            numberOfInputs: context.destination.numberOfInputs,
            numberOfOutputs: context.destination.numberOfOutputs,
            channelCount: context.destination.channelCount
        };
        """
        try:
            audio_data = driver.execute_script(script)
            return audio_data
        except:
            return {'error': 'Audio test failed'}

    def test_fonts(self, driver) -> Dict:
        """Test font fingerprint."""
        script = """
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testString = 'mmmmmmmmmmlli';
        const testSize = '72px';
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');

        const baseFontWidths = {};
        for (const baseFont of baseFonts) {
            ctx.font = testSize + ' ' + baseFont;
            baseFontWidths[baseFont] = ctx.measureText(testString).width;
        }

        const fontsToTest = [
            'Arial', 'Verdana', 'Times New Roman', 'Courier New',
            'Georgia', 'Palatino', 'Garamond', 'Comic Sans MS',
            'Trebuchet MS', 'Impact', 'Arial Black'
        ];

        const detectedFonts = [];
        for (const font of fontsToTest) {
            for (const baseFont of baseFonts) {
                ctx.font = testSize + ' ' + font + ',' + baseFont;
                const width = ctx.measureText(testString).width;
                if (width !== baseFontWidths[baseFont]) {
                    detectedFonts.push(font);
                    break;
                }
            }
        }

        return detectedFonts;
        """
        try:
            fonts = driver.execute_script(script)
            return {
                'detected_fonts': fonts,
                'count': len(fonts)
            }
        except:
            return {'error': 'Font test failed'}

    def test_screen(self, driver) -> Dict:
        """Test screen resolution."""
        script = """
        return {
            width: screen.width,
            height: screen.height,
            availWidth: screen.availWidth,
            availHeight: screen.availHeight,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth,
            devicePixelRatio: window.devicePixelRatio
        };
        """
        return driver.execute_script(script)

    def test_hardware(self, driver) -> Dict:
        """Test hardware concurrency."""
        script = """
        return {
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory || 'not available',
            platform: navigator.platform,
            vendor: navigator.vendor
        };
        """
        return driver.execute_script(script)

    def test_navigator(self, driver) -> Dict:
        """Test navigator properties."""
        script = """
        return {
            userAgent: navigator.userAgent,
            language: navigator.language,
            languages: navigator.languages,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            maxTouchPoints: navigator.maxTouchPoints
        };
        """
        return driver.execute_script(script)

    def test_timezone(self, driver) -> Dict:
        """Test timezone."""
        script = """
        return {
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezoneOffset: new Date().getTimezoneOffset()
        };
        """
        return driver.execute_script(script)

    def test_webrtc(self, driver) -> Dict:
        """Test for WebRTC IP leaks."""
        script = """
        return new Promise((resolve) => {
            const RTCPeerConnection = window.RTCPeerConnection ||
                                     window.mozRTCPeerConnection ||
                                     window.webkitRTCPeerConnection;

            if (!RTCPeerConnection) {
                resolve({error: 'WebRTC not available'});
                return;
            }

            const pc = new RTCPeerConnection({iceServers: []});
            const ips = [];

            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));

            pc.onicecandidate = (ice) => {
                if (!ice || !ice.candidate || !ice.candidate.candidate) {
                    resolve({ips: ips, leaked: ips.length > 0});
                    return;
                }

                const parts = ice.candidate.candidate.split(' ');
                const ip = parts[4];
                if (ip && !ips.includes(ip)) {
                    ips.push(ip);
                }
            };

            setTimeout(() => {
                pc.close();
                resolve({ips: ips, leaked: ips.length > 0});
            }, 2000);
        });
        """
        try:
            return driver.execute_script(script)
        except:
            return {'error': 'WebRTC test failed'}

    def compare_fingerprints(self, fingerprint1: Dict, fingerprint2: Dict) -> Dict:
        """
        Compare two fingerprints to check uniqueness.

        Args:
            fingerprint1: First fingerprint
            fingerprint2: Second fingerprint

        Returns:
            Comparison results
        """
        differences = []

        # Compare hashes
        if fingerprint1.get('fingerprint_hash') == fingerprint2.get('fingerprint_hash'):
            return {
                'identical': True,
                'uniqueness_score': 0.0,
                'differences': []
            }

        # Compare individual components
        components = ['canvas', 'webgl', 'audio', 'fonts', 'screen', 'hardware', 'navigator', 'timezone']

        for component in components:
            if fingerprint1.get(component) != fingerprint2.get(component):
                differences.append(component)

        uniqueness_score = len(differences) / len(components)

        return {
            'identical': False,
            'uniqueness_score': uniqueness_score,
            'differences': differences,
            'total_components': len(components),
            'different_components': len(differences)
        }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

if __name__ == "__main__":
    print("="*80)
    print("FINGERPRINT TESTER DEMONSTRATION")
    print("="*80)
    print()

    print("ℹ️  This utility tests browser fingerprint spoofing effectiveness")
    print()

    print("Usage:")
    print("  from fingerprint_tester import FingerprintTester")
    print("  tester = FingerprintTester()")
    print("  results = tester.test_all(driver)")
    print("  print(json.dumps(results, indent=2))")
    print()

    print("Tests performed:")
    print("  1. Canvas fingerprint")
    print("  2. WebGL vendor/renderer")
    print("  3. Audio context fingerprint")
    print("  4. Font detection")
    print("  5. Screen resolution")
    print("  6. Hardware concurrency")
    print("  7. Navigator properties")
    print("  8. Timezone")
    print("  9. WebRTC IP leak detection")
    print()

    print("="*80)
