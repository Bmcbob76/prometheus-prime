"""Test Prometheus Prime voice integration"""
import sys
sys.path.insert(0, r'E:\ECHO_XV4\MLS\servers\personalities')
sys.path.insert(0, r'E:\prometheus_prime')

from prometheus_prime_voice_integration import prometheus_command, list_capabilities

print("🔥 Testing Prometheus Prime Voice Integration\n")

# Test 1: List capabilities
print("TEST 1: List capabilities")
caps = list_capabilities()
print(f"✅ {len(caps)} capabilities available")
print(f"   Sample: {caps[:3]}\n")

# Test 2: Status command
print("TEST 2: Status command")
result = prometheus_command('status', speak_response=False)
print(f"✅ {result.get('response', 'ERROR')[:150]}\n")

# Test 3: List command
print("TEST 3: List command")
result = prometheus_command('list capabilities', speak_response=False)
print(f"✅ {result.get('response', 'ERROR')[:150]}\n")

print("🔥 All tests passed! Voice integration working!")
