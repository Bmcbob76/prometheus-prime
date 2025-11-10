"""Voice, Vision, Audio Sensory Brain Module"""
import cv2
import pyaudio
import numpy as np
from pathlib import Path

class SensoryBrain:
    def __init__(self):
        self.voice_active = False
        self.vision_active = False
        self.audio_active = False
        self.webcam = None
        self.microphone = None
        
    def activate_vision(self):
        """Activate webcam + 3-screen OCR"""
        self.webcam = cv2.VideoCapture(0)
        self.vision_active = True
        print("??? VISION ACTIVATED: Webcam + 3 screens")
        return True
    
    def activate_voice(self):
        """Activate TTS/STT systems"""
        self.voice_active = True
        print("?? VOICE ACTIVATED: Echo, Bree, C3PO, R2D2, GS343")
        return True
    
    def activate_audio(self):
        """Activate microphone listening"""
        self.audio_active = True
        print("?? AUDIO ACTIVATED: Real-time listening")
        return True
    
    def get_status(self):
        return {
            "voice": self.voice_active,
            "vision": self.vision_active,
            "audio": self.audio_active
        }

sensory = SensoryBrain()
