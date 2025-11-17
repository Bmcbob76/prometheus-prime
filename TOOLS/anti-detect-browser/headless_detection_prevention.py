#!/usr/bin/env python3
"""
PROMETHEUS PRIME - HEADLESS DETECTION PREVENTION
Prevent automation detection via navigator.webdriver and headless browser signatures

Authority Level: 11.0
Commander: Bobby Don McWilliams II

Purpose: Make Selenium/Puppeteer browsers appear as genuine user browsers

Headless Detection Methods Businesses Use:
  ❌ navigator.webdriver = true
  ❌ Missing window.chrome object
  ❌ Missing plugins (PDF Viewer, etc.)
  ❌ Missing notification permissions
  ❌ CDP (Chrome DevTools Protocol) detection
  ❌ Selenium atoms presence
  ❌ Missing browser-specific properties
  ❌ Incorrect permissions API behavior
  ❌ Automation framework signatures

This Module Prevents:
  ✅ navigator.webdriver spoofing
  ✅ Chrome runtime object injection
  ✅ Plugin enumeration fixing
  ✅ Selenium atoms removal
  ✅ CDP detection prevention
  ✅ Automation signature removal
  ✅ Headless mode property fixing
"""

import random
from typing import Dict, List


class HeadlessDetectionPrevention:
    """
    Comprehensive headless browser detection prevention scripts.
    """

    @staticmethod
    def get_navigator_webdriver_spoof() -> str:
        """Remove navigator.webdriver property that reveals automation."""
        return """
        // Remove navigator.webdriver (primary automation indicator)
        (function() {
            delete Object.getPrototypeOf(navigator).webdriver;

            Object.defineProperty(navigator, 'webdriver', {
                get: () => false,
                configurable: true
            });

            // Also override in the prototype chain
            Object.defineProperty(Navigator.prototype, 'webdriver', {
                get: () => false,
                configurable: true
            });

            console.log('[OMEGA] navigator.webdriver set to false');
        })();
        """

    @staticmethod
    def get_chrome_runtime_injection() -> str:
        """Inject missing window.chrome object that headless Chrome lacks."""
        return """
        // Inject window.chrome object (missing in headless mode)
        (function() {
            if (!window.chrome) {
                window.chrome = {
                    runtime: {
                        connect: function() {},
                        sendMessage: function() {},
                        onMessage: {
                            addListener: function() {},
                            removeListener: function() {}
                        },
                        onMessageExternal: {
                            addListener: function() {},
                            removeListener: function() {}
                        },
                        id: undefined
                    },
                    loadTimes: function() {
                        return {
                            requestTime: performance.now() / 1000 - Math.random() * 0.5,
                            startLoadTime: performance.now() / 1000 - Math.random() * 0.3,
                            commitLoadTime: performance.now() / 1000 - Math.random() * 0.2,
                            finishDocumentLoadTime: performance.now() / 1000 - Math.random() * 0.1,
                            finishLoadTime: performance.now() / 1000,
                            firstPaintTime: performance.now() / 1000 - Math.random() * 0.05,
                            firstPaintAfterLoadTime: 0,
                            navigationType: 'Other',
                            wasFetchedViaSpdy: false,
                            wasNpnNegotiated: true,
                            npnNegotiatedProtocol: 'h2',
                            wasAlternateProtocolAvailable: false,
                            connectionInfo: 'h2'
                        };
                    },
                    csi: function() {
                        return {
                            startE: Date.now(),
                            onloadT: Date.now() + Math.random() * 1000,
                            pageT: Math.random() * 500,
                            tran: 15
                        };
                    }
                };

                console.log('[OMEGA] window.chrome object injected');
            }
        })();
        """

    @staticmethod
    def get_permissions_fix() -> str:
        """Fix Permissions API behavior that differs in headless mode."""
        return """
        // Fix Permissions API (behaves differently in headless)
        (function() {
            const originalQuery = navigator.permissions.query;

            navigator.permissions.query = function(parameters) {
                // Headless Chrome always returns 'denied' for notifications
                // Real browsers return 'default' or 'prompt'
                if (parameters.name === 'notifications') {
                    return Promise.resolve({
                        state: 'default',
                        onchange: null
                    });
                }

                return originalQuery.apply(this, arguments);
            };

            console.log('[OMEGA] Permissions API behavior fixed');
        })();
        """

    @staticmethod
    def get_selenium_atoms_removal() -> str:
        """Remove Selenium-specific JavaScript atoms that reveal automation."""
        return """
        // Remove Selenium atoms (automation framework signatures)
        (function() {
            // Remove document properties added by Selenium
            delete document.__webdriver_script_fn;
            delete document.__selenium_unwrapped;
            delete document.__webdriver_unwrapped;
            delete document.__driver_evaluate;
            delete document.__webdriver_evaluate;
            delete document.__selenium_evaluate;
            delete document.__fxdriver_evaluate;
            delete document.__driver_unwrapped;
            delete document.__fxdriver_unwrapped;
            delete document.__webdriver_script_func;
            delete document.__webdriver_script_function;

            // Remove window properties
            delete window._Selenium_IDE_Recorder;
            delete window._selenium;
            delete window.__selenium_unwrapped;
            delete window.__selenium_evaluate;
            delete window.__webdriver_evaluate;
            delete window.__driver_evaluate;
            delete window.__webdriver_script_func;
            delete window.__webdriver_script_fn;
            delete window.webdriver;
            delete window.__driver_unwrapped;
            delete window.__webdriver_unwrapped;
            delete window.__fxdriver_unwrapped;
            delete window.__fxdriver_evaluate;
            delete window.Cypress;
            delete window.cy;

            // Remove $cdc_ and $wdc_ prefixed variables (ChromeDriver)
            for (let prop in window) {
                if (prop.startsWith('$cdc_') || prop.startsWith('$wdc_') || prop.startsWith('$chrome_')) {
                    delete window[prop];
                }
            }

            // Remove document.$cdc_ variables
            for (let prop in document) {
                if (prop.startsWith('$cdc_') || prop.startsWith('$wdc_')) {
                    delete document[prop];
                }
            }

            console.log('[OMEGA] Selenium atoms removed');
        })();
        """

    @staticmethod
    def get_cdp_detection_prevention() -> str:
        """Prevent Chrome DevTools Protocol detection."""
        return """
        // Prevent CDP (Chrome DevTools Protocol) detection
        (function() {
            // Override console.debug to hide CDP debugging
            const originalConsoleDebug = console.debug;
            console.debug = function(...args) {
                // Filter out CDP-related debug messages
                const message = args.join(' ');
                if (!message.includes('DevTools') && !message.includes('CDP')) {
                    originalConsoleDebug.apply(console, args);
                }
            };

            // Prevent detection via Performance API
            const originalMark = performance.mark;
            performance.mark = function(name) {
                // Don't create marks for automation-related events
                if (!name.includes('webdriver') && !name.includes('automation')) {
                    return originalMark.apply(this, arguments);
                }
            };

            // Override Error stack traces that might reveal automation
            const OriginalError = Error;
            Error = function(...args) {
                const error = new OriginalError(...args);
                // Clean stack trace of automation signatures
                if (error.stack) {
                    error.stack = error.stack
                        .replace(/\\bat .*selenium.*\\b/gi, '')
                        .replace(/\\bat .*webdriver.*\\b/gi, '')
                        .replace(/\\bat .*puppeteer.*\\b/gi, '')
                        .replace(/\\bat .*playwright.*\\b/gi, '');
                }
                return error;
            };
            Error.prototype = OriginalError.prototype;

            console.log('[OMEGA] CDP detection prevented');
        })();
        """

    @staticmethod
    def get_headless_chrome_fixes() -> str:
        """Fix properties that are different in headless Chrome."""
        return """
        // Fix headless Chrome-specific properties
        (function() {
            // Headless Chrome has different connection values
            if (navigator.connection) {
                Object.defineProperty(navigator.connection, 'rtt', {
                    get: () => Math.floor(Math.random() * 50) + 10
                });
            }

            // Fix missing properties in headless mode
            if (!navigator.getBattery) {
                navigator.getBattery = function() {
                    return Promise.resolve({
                        charging: true,
                        chargingTime: 0,
                        dischargingTime: Infinity,
                        level: 1.0,
                        addEventListener: function() {},
                        removeEventListener: function() {},
                        dispatchEvent: function() { return true; }
                    });
                };
            }

            // Fix userActivation (missing in old headless)
            if (!navigator.userActivation) {
                navigator.userActivation = {
                    hasBeenActive: true,
                    isActive: true
                };
            }

            console.log('[OMEGA] Headless Chrome properties fixed');
        })();
        """

    @staticmethod
    def get_iframe_contentwindow_fix() -> str:
        """Fix iframe contentWindow detection method."""
        return """
        // Fix iframe contentWindow detection
        (function() {
            const originalCreateElement = document.createElement;

            document.createElement = function(tagName) {
                const element = originalCreateElement.call(document, tagName);

                if (tagName.toLowerCase() === 'iframe') {
                    // Override contentWindow to prevent headless detection
                    Object.defineProperty(element, 'contentWindow', {
                        get: function() {
                            const win = originalCreateElement.call(document, 'iframe').contentWindow;
                            // Ensure navigator.webdriver is false in iframes too
                            if (win && win.navigator) {
                                Object.defineProperty(win.navigator, 'webdriver', {
                                    get: () => false
                                });
                            }
                            return win;
                        }
                    });
                }

                return element;
            };

            console.log('[OMEGA] iframe contentWindow detection prevented');
        })();
        """

    @staticmethod
    def get_automation_detection_evasion() -> str:
        """Evade common automation detection techniques."""
        return """
        // Evade automation detection techniques
        (function() {
            // 1. Outsmart detection via toString on functions
            const originalToString = Function.prototype.toString;
            Function.prototype.toString = function() {
                // Return native code for overridden functions to hide our modifications
                if (this === navigator.permissions.query ||
                    this === HTMLCanvasElement.prototype.toDataURL ||
                    this === WebGLRenderingContext.prototype.getParameter) {
                    return 'function () { [native code] }';
                }
                return originalToString.call(this);
            };

            // 2. Fix missing outerHeight/outerWidth in headless
            if (window.outerWidth === 0) {
                Object.defineProperty(window, 'outerWidth', {
                    get: () => window.innerWidth
                });
            }
            if (window.outerHeight === 0) {
                Object.defineProperty(window, 'outerHeight', {
                    get: () => window.innerHeight + 85 // Add browser chrome height
                });
            }

            // 3. Fix missing Notification in headless
            if (!window.Notification) {
                window.Notification = class Notification {
                    constructor(title, options) {
                        this.title = title;
                        this.body = options.body;
                    }
                    static requestPermission() {
                        return Promise.resolve('default');
                    }
                };
            }

            // 4. Add missing mozInnerScreenX/Y (Firefox-specific but checked by some detectors)
            if (typeof window.mozInnerScreenX === 'undefined') {
                Object.defineProperty(window, 'mozInnerScreenX', {
                    get: () => 0
                });
                Object.defineProperty(window, 'mozInnerScreenY', {
                    get: () => 0
                });
            }

            console.log('[OMEGA] Automation detection evasion applied');
        })();
        """

    @staticmethod
    def get_combined_headless_prevention() -> str:
        """Combine all headless detection prevention techniques."""
        scripts = [
            HeadlessDetectionPrevention.get_navigator_webdriver_spoof(),
            HeadlessDetectionPrevention.get_chrome_runtime_injection(),
            HeadlessDetectionPrevention.get_permissions_fix(),
            HeadlessDetectionPrevention.get_selenium_atoms_removal(),
            HeadlessDetectionPrevention.get_cdp_detection_prevention(),
            HeadlessDetectionPrevention.get_headless_chrome_fixes(),
            HeadlessDetectionPrevention.get_iframe_contentwindow_fix(),
            HeadlessDetectionPrevention.get_automation_detection_evasion()
        ]

        combined = "\n\n".join(scripts)
        return f"""
        (function() {{
            'use strict';

            console.log('[OMEGA PRIME ECHO] Applying headless detection prevention...');

            {combined}

            console.log('[OMEGA PRIME ECHO] Headless detection prevention complete');
            console.log('[OMEGA PRIME ECHO] Browser now appears as genuine user browser');
        }})();
        """


# ═══════════════════════════════════════════════════════════════════════════
# USAGE EXAMPLE
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("="*80)
    print("HEADLESS DETECTION PREVENTION DEMONSTRATION")
    print("="*80)
    print()

    print("🛡️  Headless Detection Prevention Features:")
    print("  ✓ navigator.webdriver = false")
    print("  ✓ window.chrome object injection")
    print("  ✓ Permissions API behavior fixing")
    print("  ✓ Selenium atoms removal")
    print("  ✓ CDP detection prevention")
    print("  ✓ Headless Chrome property fixes")
    print("  ✓ iframe contentWindow fixing")
    print("  ✓ Automation detection evasion")
    print()

    # Generate prevention script
    script = HeadlessDetectionPrevention.get_combined_headless_prevention()

    print("Generated prevention script:")
    print(f"  Length: {len(script)} characters")
    print(f"  Techniques: 8 comprehensive methods")
    print()

    print("Usage with Selenium:")
    print("  driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {")
    print("      'source': HeadlessDetectionPrevention.get_combined_headless_prevention()")
    print("  })")
    print()

    print("="*80)
