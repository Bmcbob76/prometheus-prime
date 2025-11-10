#!/usr/bin/env python3
"""
Quick ElevenLabs API Key Test
Tests both keys found in .env file
"""

import os
import sys
import tempfile

# Test keys
KEYS = [
    ("Key #1", "sk_1921246f88b8fbecdb0cc047774eae7523043b180389d308"),
    ("Key #2", "sk_2c0f0020651d25cc93485dfabfe000b7d3355f930ad44ea5")
]

print("="*70)
print("🔑 ELEVENLABS API KEY TEST")
print("="*70)

# Install if needed
try:
    from elevenlabs.client import ElevenLabs
    from elevenlabs import VoiceSettings
    print("✅ ElevenLabs library available")
except ImportError:
    print("📦 Installing ElevenLabs...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "elevenlabs", "--upgrade", "--quiet"])
    from elevenlabs.client import ElevenLabs
    from elevenlabs import VoiceSettings
    print("✅ ElevenLabs installed")

# Test both keys
for key_name, key_value in KEYS:
    print(f"\n{'='*70}")
    print(f"Testing {key_name}")
    print(f"Key: {key_value[:20]}...{key_value[-10:]}")
    print("="*70)
    
    try:
        # Create client with API key
        client = ElevenLabs(api_key=key_value)
        
        # Generate short test
        test_text = "Prometheus Prime operational. All systems nominal."
        print(f"🎙️  Generating test audio: '{test_text}'")
        
        # Correct v3 API: text_to_speech.convert()
        audio = client.text_to_speech.convert(
            text=test_text,
            voice_id="21m00Tcm4TlvDq8ikWAM",  # Rachel
            model_id="eleven_multilingual_v2"
        )
        
        # Save to temp
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.mp3')
        
        # Write audio bytes
        with open(temp_file.name, 'wb') as f:
            for chunk in audio:
                f.write(chunk)
        
        file_size = os.path.getsize(temp_file.name)
        print(f"✅ SUCCESS - Generated {file_size} bytes")
        print(f"   File: {temp_file.name}")
        
        # Cleanup
        try:
            os.unlink(temp_file.name)
        except:
            pass
            
        print(f"\n🎉 {key_name} WORKS PERFECTLY!")
        break  # Stop on first success
        
    except Exception as e:
        print(f"❌ FAILED:")
        print(f"   Error type: {type(e).__name__}")
        print(f"   Full error: {str(e)}")
        if hasattr(e, 'status_code'):
            print(f"   Status code: {e.status_code}")
        if hasattr(e, 'body'):
            print(f"   Body: {e.body}")
        continue

print("\n" + "="*70)
print("🏁 TEST COMPLETE")
print("="*70)
